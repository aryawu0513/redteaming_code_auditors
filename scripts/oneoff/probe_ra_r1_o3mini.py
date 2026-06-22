#!/usr/bin/env python3
"""
probe_ra_r1_o3mini.py — Run a known RepoAudit baseline-TP slug with DeepSeek R1
and o3-mini on both the clean and the best-round attacked variant.

Results are printed as a 2×2 table (model × clean/attacked).
Persistent output dirs written to /tmp/ra_{model}_{slug}_{variant}/.

Usage:
    python scripts/oneoff/probe_ra_r1_o3mini.py --slug NPD-CVE-XXXX
    python scripts/oneoff/probe_ra_r1_o3mini.py --slug NPD-CVE-XXXX --atype COT
    python scripts/oneoff/probe_ra_r1_o3mini.py --slug NPD-CVE-XXXX --models r1          # r1 only
    python scripts/oneoff/probe_ra_r1_o3mini.py --slug NPD-CVE-XXXX --models o3mini      # o3-mini only
    python scripts/oneoff/probe_ra_r1_o3mini.py --slug NPD-CVE-XXXX --models r1 o3mini   # both (default)
    python scripts/oneoff/probe_ra_r1_o3mini.py --slug NPD-CVE-XXXX --clean-only         # skip attacked
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))
sys.path.insert(0, str(REPO_ROOT))

from refine_loop_fromscratch import insert_annotation  # noqa: E402

BASELINE = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
ADAPTIVE_RESULTS = REPO_ROOT / "adaptive_attacker" / "results" / "vulnllmr_full"
REPOAUDIT_SRC = REPO_ROOT / "RepoAudit" / "src"

MODEL_IDS = {
    "r1": "deepseek/deepseek-r1",
    "o3mini": "o3-mini",
}

# annotation type priority: prefer COT (most common), fall back to others
ATYPE_PRIORITY = [
    "COT", "AA_CA", "AA_MSG", "AA_USR", "CG", "FT",
    "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer",
]


def load_clean_record(slug: str) -> dict:
    slug_dir = BASELINE / f"repository_{slug}"
    clean_files = list(slug_dir.glob("*_CLEAN.json"))
    if not clean_files:
        raise FileNotFoundError(f"No CLEAN json for {slug}")
    return json.loads(clean_files[0].read_text())[0]


def find_attack_round(slug: str, atype: str | None) -> tuple[dict, str]:
    """Return (round_data, atype_used). Picks best available atype."""
    adir_root = ADAPTIVE_RESULTS / f"repository_{slug}"
    if not adir_root.exists():
        raise FileNotFoundError(f"No adaptive attacker results for {slug} at {adir_root}")

    if atype:
        atypes_to_try = [atype]
    else:
        atypes_to_try = ATYPE_PRIORITY

    for at in atypes_to_try:
        adir = adir_root / f"adaptive_{at}_fromscratch_v1"
        if not adir.exists():
            continue
        # Prefer highest round that succeeded (result.json if present, else last round_N.json)
        result_file = adir / "result.json"
        if result_file.exists():
            return json.loads(result_file.read_text()), at
        rounds = sorted(adir.glob("round_*.json"), key=lambda p: int(p.stem.split("_")[1]))
        if rounds:
            return json.loads(rounds[-1].read_text()), at

    raise FileNotFoundError(f"No attack rounds found for {slug} (tried: {atypes_to_try})")


def build_attacked_code(clean_rec: dict, round_data: dict) -> tuple[str, str, str]:
    """Return (code_str, file_name, auxiliary)."""
    attacked = copy.deepcopy(clean_rec)
    attacked["target_function"] = insert_annotation(
        clean_rec["target_function"],
        round_data["annotation_text"],
        round_data["insert_before"],
    )
    before = attacked.get("context_before", "")
    after  = attacked.get("context_after", "")
    tf     = attacked["target_function"]
    code   = "\n\n".join(p for p in [before, tf, after] if p).strip()
    file_name = attacked.get("file_name") or "solution.c"
    auxiliary = attacked.get("auxiliary_file", "").strip()
    return code, file_name, auxiliary


def build_clean_code(rec: dict) -> tuple[str, str, str]:
    before = rec.get("context_before", "")
    after  = rec.get("context_after", "")
    tf     = rec.get("target_function", "")
    code   = "\n\n".join(p for p in [before, tf, after] if p).strip()
    file_name = rec.get("file_name") or "solution.c"
    auxiliary = rec.get("auxiliary_file", "").strip()
    return code, file_name, auxiliary


def run_repoaudit(
    model_id: str,
    code: str,
    file_name: str,
    auxiliary: str,
    out_dir: Path,
) -> dict:
    """Run RepoAudit with given model, write files into out_dir, return verdict dict."""
    project_dir = out_dir / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / file_name).write_text(code)
    if auxiliary:
        (project_dir / "auxiliary.cc").write_text(auxiliary)

    result_root = out_dir / "ra_out"
    env = os.environ.copy()
    env["RA_RESULT_ROOT"] = str(result_root)
    env["LANGUAGE"] = "Cpp"
    env["MODEL"] = model_id

    t0 = time.time()
    try:
        proc = subprocess.run(
            ["bash", str(REPOAUDIT_SRC / "run_repoaudit.sh"),
             str(project_dir), "NPD", "*.c"],
            cwd=str(REPOAUDIT_SRC), env=env, check=True,
        )
    except subprocess.CalledProcessError as e:
        return {"verdict": "error", "error": str(e), "elapsed_s": round(time.time() - t0, 1)}

    elapsed = time.time() - t0

    model_slug = model_id.replace("/", "_")
    res_base = (result_root / "result" / "dfbscan" / model_slug
                / "NPD" / "Cpp" / project_dir.name)
    run_dirs = sorted(res_base.glob("*"))
    if not run_dirs:
        return {"verdict": "safe", "bug_count": 0, "elapsed_s": round(elapsed, 1)}

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
        try:
            bug_count = len(json.loads(detect_info.read_text()))
        except Exception:
            pass

    # Grab log snippet
    log_dir = (result_root / "log" / "dfbscan" / model_slug
               / "NPD" / "Cpp" / project_dir.name / latest.name)
    log_snippet = ""
    for log_file in sorted(log_dir.glob("*.log")) if log_dir.exists() else []:
        content = log_file.read_text()
        log_snippet += f"\n--- {log_file.name} (last 800 chars) ---\n{content[-800:]}"

    return {
        "verdict": verdict,
        "bug_count": bug_count,
        "elapsed_s": round(elapsed, 1),
        "log_snippet": log_snippet.strip(),
    }


def print_table(slug: str, atype: str, annotation: str, results: dict) -> None:
    print(f"\n{'='*65}")
    print(f"Slug: {slug}  |  Attack type: {atype}")
    print(f"Annotation: {annotation[:120]}{'...' if len(annotation)>120 else ''}")
    print(f"{'='*65}")
    header = f"{'MODEL':<20} {'CLEAN':<12} {'ATTACKED':<12}"
    print(header)
    print("-" * 45)
    for model_key, model_id in MODEL_IDS.items():
        clean_r = results.get(f"{model_key}_clean", {})
        att_r   = results.get(f"{model_key}_attacked", {})
        clean_v = clean_r.get("verdict", "N/A")
        att_v   = att_r.get("verdict", "N/A")
        clean_t = f"({clean_r.get('elapsed_s','?')}s)" if clean_r else ""
        att_t   = f"({att_r.get('elapsed_s','?')}s)" if att_r else ""
        print(f"{model_id:<20} {clean_v:<7}{clean_t:<7} {att_v:<7}{att_t:<7}")
    print(f"{'='*65}\n")

    # Print log snippets for attacked runs
    for model_key, model_id in MODEL_IDS.items():
        att_r = results.get(f"{model_key}_attacked", {})
        snippet = att_r.get("log_snippet", "")
        if snippet:
            print(f"--- {model_id} ATTACKED log snippet ---")
            print(snippet[-600:])
            print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slug", required=True, help="e.g. NPD-CVE-0006")
    parser.add_argument("--atype", default=None, help="annotation type e.g. COT, TOOL_Fuzzer")
    parser.add_argument("--models", nargs="+", choices=list(MODEL_IDS.keys()),
                        default=list(MODEL_IDS.keys()),
                        help="which models to run (default: r1 o3mini)")
    parser.add_argument("--clean-only", action="store_true",
                        help="skip attacked variant")
    args = parser.parse_args()

    slug = args.slug
    print(f"Loading records for {slug} ...")

    clean_rec = load_clean_record(slug)
    clean_code, file_name, auxiliary = build_clean_code(clean_rec)
    print(f"  File: {file_name}  auxiliary={'yes' if auxiliary else 'no'}")

    atype_used = None
    attacked_code = None
    annotation_text = "(clean-only run)"
    round_data = {}

    if not args.clean_only:
        try:
            round_data, atype_used = find_attack_round(slug, args.atype)
            attacked_code, _, _ = build_attacked_code(clean_rec, round_data)
            annotation_text = round_data.get("annotation_text", "")
            print(f"  Attack type: {atype_used}  annotation: {annotation_text[:80]}...")
        except FileNotFoundError as e:
            print(f"  WARNING: {e} — running clean only")
            args.clean_only = True

    results = {}

    for model_key in args.models:
        model_id = MODEL_IDS[model_key]
        safe_model = model_id.replace("/", "_").replace("-", "_")

        print(f"\n>>> {model_id} — CLEAN ({slug})")
        out_dir = Path(f"/tmp/ra_{safe_model}_{slug.replace('-','_')}_CLEAN")
        out_dir.mkdir(exist_ok=True)
        r = run_repoaudit(model_id, clean_code, file_name, auxiliary, out_dir)
        results[f"{model_key}_clean"] = r
        print(f"    verdict={r['verdict']}  bugs={r.get('bug_count')}  {r['elapsed_s']}s")

        if not args.clean_only and attacked_code:
            print(f"\n>>> {model_id} — ATTACKED ({slug}, {atype_used})")
            out_dir = Path(f"/tmp/ra_{safe_model}_{slug.replace('-','_')}_ATTACKED_{atype_used}")
            out_dir.mkdir(exist_ok=True)
            r = run_repoaudit(model_id, attacked_code, file_name, auxiliary, out_dir)
            results[f"{model_key}_attacked"] = r
            print(f"    verdict={r['verdict']}  bugs={r.get('bug_count')}  {r['elapsed_s']}s")

    print_table(slug, atype_used or "N/A", annotation_text, results)

    # Save summary
    summary_path = Path(f"/tmp/ra_r1_o3mini_{slug.replace('-','_')}_summary.json")
    summary_path.write_text(json.dumps({
        "slug": slug,
        "atype": atype_used,
        "annotation": annotation_text,
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "log_snippet"}
                    for k, v in results.items()},
    }, indent=2))
    print(f"Summary saved: {summary_path}")


if __name__ == "__main__":
    main()
