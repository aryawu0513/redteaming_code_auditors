#!/usr/bin/env python3
"""
probe_ra_find_tps.py — Sweep cvebench_full slugs with RepoAudit to find baseline-TPs:
slugs where the TARGET model detects the NPD on clean, unattacked code.

The model must match the one you'll use for the attack run — a gpt-5-mini TP
tells you nothing about whether R1 or o3-mini will detect it.

Results are saved incrementally to /tmp/ra_tp_sweep_{model_safe}.json (resumable).
Only scans NULL-bearing slugs (89/128) since the others are structural FNs.

Usage:
    python scripts/oneoff/probe_ra_find_tps.py [--model deepseek/deepseek-r1] [--max N]
    python scripts/oneoff/probe_ra_find_tps.py --model o3-mini --max 10
    python scripts/oneoff/probe_ra_find_tps.py --slug NPD-CVE-0006 NPD-CVE-0025
    python scripts/oneoff/probe_ra_find_tps.py --show  # print accumulated results only
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))
sys.path.insert(0, str(REPO_ROOT))

BASELINE = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
REPOAUDIT_SRC = REPO_ROOT / "RepoAudit" / "src"


def results_file(model: str) -> Path:
    safe = model.replace("/", "_").replace("-", "_")
    return Path(f"/tmp/ra_tp_sweep_{safe}.json")


def load_results(model: str) -> dict:
    f = results_file(model)
    if f.exists():
        return json.loads(f.read_text())
    return {}


def save_results(results: dict, model: str) -> None:
    results_file(model).write_text(json.dumps(results, indent=2))


def has_null(rec: dict) -> bool:
    tf = rec.get("target_function", "")
    cb = rec.get("context_before", "")
    ca = rec.get("context_after", "")
    return "NULL" in (tf + cb + ca) or "nullptr" in (tf + cb + ca)


def all_slugs() -> list[str]:
    return sorted(
        d.name.replace("repository_", "")
        for d in BASELINE.glob("repository_NPD-CVE-*")
    )


def null_slugs() -> list[str]:
    slugs = []
    for d in sorted(BASELINE.glob("repository_NPD-CVE-*")):
        slug = d.name.replace("repository_", "")
        clean_files = list(d.glob("*_CLEAN.json"))
        if not clean_files:
            continue
        rec = json.loads(clean_files[0].read_text())[0]
        if has_null(rec):
            slugs.append(slug)
    return slugs


def run_repoaudit_clean(slug: str, model: str) -> dict:
    slug_dir = BASELINE / f"repository_{slug}"
    clean_files = list(slug_dir.glob("*_CLEAN.json"))
    if not clean_files:
        return {"verdict": "error", "error": "no CLEAN json"}
    rec = json.loads(clean_files[0].read_text())[0]

    before = rec.get("context_before", "")
    after  = rec.get("context_after", "")
    tf     = rec.get("target_function", "")
    code   = "\n\n".join(p for p in [before, tf, after] if p).strip()
    file_name = rec.get("file_name") or "solution.c"
    auxiliary = rec.get("auxiliary_file", "").strip()

    with tempfile.TemporaryDirectory(prefix=f"ra_tpsweep_{slug}_") as tmp:
        project_dir = Path(tmp) / "project"
        project_dir.mkdir(parents=True)
        (project_dir / file_name).write_text(code)
        if auxiliary:
            (project_dir / "auxiliary.cc").write_text(auxiliary)

        result_root = Path(tmp) / "ra_out"
        env = os.environ.copy()
        env["RA_RESULT_ROOT"] = str(result_root)
        env["LANGUAGE"] = "Cpp"
        env["MODEL"] = model

        try:
            subprocess.run(
                ["bash", str(REPOAUDIT_SRC / "run_repoaudit.sh"),
                 str(project_dir), "NPD", "*.c"],
                cwd=str(REPOAUDIT_SRC), env=env, check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            return {"verdict": "error", "error": str(e.stderr[-500:])}

        model_slug = model.replace("/", "_")
        res_base = (result_root / "result" / "dfbscan" / model_slug
                    / "NPD" / "Cpp" / project_dir.name)
        run_dirs = sorted(res_base.glob("*"))
        if not run_dirs:
            return {"verdict": "safe", "bug_count": 0}

        latest = run_dirs[-1]
        verdict = "safe"
        for summary in latest.glob("*_summary.json"):
            sdata = json.loads(summary.read_text())
            if sdata.get("flag") == "tp":
                verdict = "vulnerable"
                break

        detect_info = latest / "detect_info.json"
        bug_count = 0
        if detect_info.exists():
            bug_count = len(json.loads(detect_info.read_text()))

        return {"verdict": verdict, "bug_count": bug_count, "model": model}


def show_summary(results: dict, model: str) -> None:
    tps = [s for s, v in results.items() if v.get("verdict") == "vulnerable"]
    fns = [s for s, v in results.items() if v.get("verdict") == "safe"]
    errs = [s for s, v in results.items() if v.get("verdict") == "error"]
    print(f"\n=== RepoAudit TP sweep ({model}) ===")
    print(f"Scanned: {len(results)}  TPs: {len(tps)}  FNs: {len(fns)}  Errors: {len(errs)}")
    if tps:
        print(f"TPs: {tps}")
    if errs:
        print(f"Errors: {errs}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="deepseek/deepseek-r1",
                        help="RepoAudit model to use (default: deepseek/deepseek-r1)")
    parser.add_argument("--max", type=int, default=None, help="max slugs to probe")
    parser.add_argument("--slug", nargs="+", help="specific slugs to probe")
    parser.add_argument("--all", action="store_true", help="scan all 128 (not just null-bearing)")
    parser.add_argument("--show", action="store_true", help="print results and exit")
    args = parser.parse_args()
    model = args.model

    results = load_results(model)

    if args.show:
        show_summary(results, model)
        return

    if args.slug:
        candidates = args.slug
    elif args.all:
        candidates = all_slugs()
    else:
        candidates = null_slugs()

    if args.max:
        candidates = candidates[: args.max]

    todo = [s for s in candidates if s not in results]
    print(f"Candidates: {len(candidates)}  Already done: {len(candidates) - len(todo)}  To run: {len(todo)}")

    print(f"Model: {model}  Results file: {results_file(model)}")

    for i, slug in enumerate(todo):
        print(f"\n[{i+1}/{len(todo)}] {slug} ...", flush=True)
        t0 = time.time()
        result = run_repoaudit_clean(slug, model)
        elapsed = time.time() - t0
        result["elapsed_s"] = round(elapsed, 1)
        results[slug] = result
        save_results(results, model)
        print(f"  → {result['verdict']} (bugs={result.get('bug_count', '?')}, {elapsed:.0f}s)")
        tps = [s for s, v in results.items() if v.get("verdict") == "vulnerable"]
        if tps:
            print(f"  TPs so far: {tps}")

    show_summary(results, model)


if __name__ == "__main__":
    main()
