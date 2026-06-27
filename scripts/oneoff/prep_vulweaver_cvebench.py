#!/usr/bin/env python3
"""
prep_vulweaver_cvebench.py — prepare cvebench_full for VulWeaver's RQ4 (C/C++)
whole-repo neuro-symbolic pipeline.

STEP-1 ANSWER (verified by reading run_simulation_primevul.py + slice.py):
  VulWeaver LOCATES the target function in the cloned repo file
  (matching_method = "<rel_file>#<func>") and slices the REAL file in place via
  Joern. It does NOT inject `target_code`. => we MUST splice our
  attacker-generated vulnerable function into the cloned target file first.

What this script does, per --tag (default cvebench_full) / --variant (default CLEAN):
  1. Reads /mnt/ssd/aryawu/cve_repos_fix/clone_manifest.json (slug -> clone_dir,
     commit, file, function, lang, repo_url). Clones are at the FIX commit, so
     the target functions are PATCHED — we overwrite them by splicing.
  2. Groups slugs by VulWeaver repo dir "<project_name>_<commit>". For each dir:
       - cp -al the fix-commit clone into target_project/<dir> (hardlink = cheap;
         the splice below breaks the link only for the one file it rewrites).
       - splices the benchmark vulnerable function into ONLY metadata["file"]
         (asserts exactly 1 replacement). Multiple slugs that share a repo dir
         each splice their own (unique) function into the shared copy.
  3. Emits primevul-schema rows -> cvebench_dataset/<tag>_<variant>.json with
     method_name == target_method == "<rel_file>#<func>" (run_simulation reads
     method_name; run_llm_reasoning reads target_method — we set both equal so
     the cache keys line up).
  4. (optional --extract-api) fills target_api_name per row via OpenRouter,
     mirroring format_primevul_dataset.llm_based_extract_api. Without it, rows
     get target_api_name=[] (slicing still runs; sensitive-api focus is just off).

Then run (Joern required — see scripts/oneoff/run_vulweaver_cvebench.sh):
  VULWEAVER_PRIMEVUL_JSON=<ds>  VULWEAVER_CACHE_DIR=<ctx>  python run_simulation_primevul.py
  python run_llm_reasoning.py --primevul-worklist <ds> --cache-dir <ctx> --lang c ...

This script is pure-Python + git/cp; fast and safe to run directly (no Joern,
no GPU). --extract-api adds one LLM call per slug (cheap) — run it yourself.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "cvebench"))
from splice_target import splice_function, find_function_spans  # noqa: E402

MANIFEST = Path("/mnt/ssd/aryawu/cve_repos_fix/clone_manifest.json")
VW_RQ4 = REPO_ROOT / "VulWeaver" / "evaluation" / "RQ4"
DEFAULT_TARGET_PROJECT = VW_RQ4 / "simulation" / "target_project"
DEFAULT_DATASET_DIR = VW_RQ4 / "cvebench_dataset"


def project_name(repo_url: str) -> str:
    return repo_url.rstrip("/").split("/")[-1].replace(".git", "")


def clean_json_path(slug: str, variant: str) -> Path:
    return (REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
            / f"repository_{slug}" / f"{slug}_{variant}.json")


def load_clean(slug: str, variant: str) -> dict:
    d = json.loads(clean_json_path(slug, variant).read_text())
    return d[0] if isinstance(d, list) else d


def copy_clone(clone_dir: Path, dest: Path) -> None:
    """Hardlink-copy the clone tree FRESH (cheap). Always rm+recopy so re-runs
    splice onto a pristine base (avoids re-splicing an already-spliced file).
    cp -al on same FS; fall back to cp -a."""
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["cp", "-al", str(clone_dir), str(dest)], check=True,
                       capture_output=True)
    except subprocess.CalledProcessError:
        subprocess.run(["cp", "-a", str(clone_dir), str(dest)], check=True)


def splice_into(dest: Path, rel_file: str, func: str, new_func: str, lang: str) -> int:
    """Splice new_func over `func` in dest/rel_file. Breaks hardlinks (remove+write).
    Returns n_replaced, or -1 if new_func is NOT a clean single definition of
    `func` (a malformed/mis-extracted drop-in, e.g. NPD-CVE-0027 — splicing it
    would corrupt the file AND break VulWeaver's file#func locate step)."""
    if len(find_function_spans(new_func, func, lang)) != 1:
        return -1
    fpath = dest / rel_file
    text = fpath.read_text(errors="replace")
    out, n = splice_function(text, func, new_func, lang)
    if n != 1:
        return n
    # Break the hardlink so we never touch the shared source clone.
    fpath.unlink()
    fpath.write_text(out)
    return n


# --- optional sensitive-API extraction (mirrors format_primevul_dataset.py) ---
def extract_api(target_code: str, cve_id: str, cwe_id: str) -> list[str]:
    import requests
    url = os.getenv("VULWEAVER_LLM_URL", "https://openrouter.ai/api/v1/chat/completions")
    model = os.getenv("VULWEAVER_LLM_MODEL", "deepseek/deepseek-chat")
    key = os.getenv("OPENROUTER_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
    if not key:
        raise RuntimeError("set OPENROUTER_API_KEY (or DEEPSEEK_API_KEY) for --extract-api")
    system = (
        "You are an expert in identifying security vulnerabilities that extracts API "
        "calls from a code snippet. Return ONLY a JSON list of the pivotal API call "
        "names, e.g. [\"fopen\"]. No markdown, no commentary."
    )
    user = (
        f"The code snippet contains a {cve_id} {cwe_id} vulnerability. Extract the "
        f"pivotal API calls as a JSON list (empty list if none).\nCode snippet:\n"
        f"```\n{target_code}\n```"
    )
    r = requests.post(url, headers={"Authorization": f"Bearer {key}",
                                    "Content-Type": "application/json"},
                      json={"model": model, "temperature": 0.0,
                            "messages": [{"role": "system", "content": system},
                                         {"role": "user", "content": user}]},
                      timeout=120)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    import re
    content = re.sub(r"```(?:json)?", "", content, flags=re.I).replace("```", "").strip()
    try:
        val = json.loads(content)
        return [a for a in val if isinstance(a, str)] if isinstance(val, list) else []
    except Exception:
        return []


def apply_annotation(func_text: str, annotation_text: str, insert_before: str,
                     inline: bool = False) -> tuple[str, bool]:
    """Inject annotation_text relative to the FIRST line whose stripped content
    matches insert_before. Mirrors the adaptive attacker's comment-injection.

    inline=False (default): insert as its own line(s) immediately BEFORE that line.
    inline=True: append as a trailing comment ON that line (collapsed to one line),
      so the annotation rides on a line that the data-flow slice actually selects
      (standalone comment lines are dropped by the slice). Returns (text, applied?)."""
    target = (insert_before or "").strip()
    if not target:
        return func_text, False
    out_lines = []
    applied = False
    for line in func_text.splitlines():
        if not applied and line.strip() == target:
            if inline:
                # collapse annotation to a single trailing // comment
                collapsed = " ".join(a.strip() for a in annotation_text.splitlines())
                if not collapsed.lstrip().startswith("//"):
                    collapsed = "// " + collapsed
                out_lines.append(line.rstrip() + "  " + collapsed)
                applied = True
                continue
            indent = line[: len(line) - len(line.lstrip())]
            for ann in annotation_text.splitlines() or [annotation_text]:
                out_lines.append(indent + ann)
            applied = True
        out_lines.append(line)
    return "\n".join(out_lines), applied


def load_attack_annotation(attack_root: Path, slug: str, attack_type: str, rnd: int) -> dict | None:
    p = attack_root / f"repository_{slug}" / attack_type / f"round_{rnd}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="cvebench_full",
                    help="output dataset/cache tag (never overwrites VulWeaver's primevul json)")
    ap.add_argument("--variant", default="CLEAN", help="benchmark variant json suffix")
    ap.add_argument("--source", default="target_function",
                    choices=["target_function", "attacker_output"],
                    help="which CLEAN.json field to splice (target_function = signature-safe drop-in)")
    ap.add_argument("--slugs", nargs="*", default=None,
                    help="explicit slugs (default: all in manifest)")
    ap.add_argument("--limit", type=int, default=None, help="cap number of slugs (sorted)")
    ap.add_argument("--target-project", default=str(DEFAULT_TARGET_PROJECT))
    ap.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR))
    ap.add_argument("--extract-api", action="store_true",
                    help="fill target_api_name via OpenRouter (1 LLM call/slug)")
    ap.add_argument("--api-workers", type=int, default=8)
    ap.add_argument("--no-copy", action="store_true",
                    help="only (re)write dataset json; skip clone-copy+splice")
    # --- attack mode: splice the round-N attack-annotated function instead of CLEAN ---
    ap.add_argument("--attack-root", default=None,
                    help="e.g. adaptive_attacker/results/vulnllmr_full — splice the attack-annotated fn")
    ap.add_argument("--attack-type", default=None,
                    help="e.g. adaptive_AA_CA_fromscratch_v1")
    ap.add_argument("--attack-round", type=int, default=5)
    ap.add_argument("--inline-annotation", action="store_true",
                    help="attach the annotation as a trailing inline comment on the "
                         "insert_before line (rides a sliced data-flow line) instead of "
                         "a standalone line before it")
    args = ap.parse_args()
    attack_root = Path(args.attack_root) if args.attack_root else None

    manifest = json.loads(MANIFEST.read_text())
    slugs = args.slugs or sorted(manifest.keys())
    if args.limit:
        slugs = slugs[: args.limit]

    target_project = Path(args.target_project)
    dataset_dir = Path(args.dataset_dir)
    dataset_dir.mkdir(parents=True, exist_ok=True)

    # Group by VulWeaver repo dir so shared repos are copied once.
    by_dir: dict[str, list[str]] = defaultdict(list)
    for slug in slugs:
        e = manifest[slug]
        d = f"{project_name(e['repo_url'])}_{e['commit']}"
        by_dir[d].append(slug)

    rows: list[dict] = []
    splice_fail: list[str] = []
    for didx, (dirname, group) in enumerate(sorted(by_dir.items())):
        dest = target_project / dirname
        rep = manifest[group[0]]
        if not args.no_copy:
            copy_clone(Path(rep["clone_dir"]), dest)
        for slug in sorted(group):
            e = manifest[slug]
            clean = load_clean(slug, args.variant)
            vuln_fn = clean[args.source]
            annotated = False
            if attack_root is not None:
                atk = load_attack_annotation(attack_root, slug, args.attack_type, args.attack_round)
                if atk is None:
                    print(f"  SKIP {slug}: no attack round_{args.attack_round} "
                          f"for {args.attack_type} under {attack_root}", flush=True)
                    splice_fail.append(slug)
                    continue
                vuln_fn, annotated = apply_annotation(
                    vuln_fn, atk.get("annotation_text", ""), atk.get("insert_before", ""),
                    inline=args.inline_annotation)
                if not annotated:
                    print(f"  WARN {slug}: insert_before line not found in target_function; "
                          f"splicing un-annotated (annotation would no-op)", flush=True)
            if not args.no_copy:
                n = splice_into(dest, e["file"], e["function"], vuln_fn, e["lang"])
                if n == -1:
                    print(f"  SKIP {slug}: malformed drop-in — {args.source} does not "
                          f"define exactly one '{e['function']}' (not signature-identical)",
                          flush=True)
                    splice_fail.append(slug)
                    continue
                if n != 1:
                    print(f"  SPLICE FAIL {slug}: replaced {n} (expected 1) of "
                          f"{e['function']} in {e['file']}", flush=True)
                    splice_fail.append(slug)
                    continue
            sig = f"{e['file']}#{e['function']}"
            cwe = clean["CWE_ID"]
            cwe = cwe[0] if isinstance(cwe, list) and cwe else (cwe if isinstance(cwe, str) else "")
            rows.append({
                "idx": didx * 1000 + sorted(group).index(slug),
                "slug": slug,
                "project_url": e["repo_url"],
                "project_name": project_name(e["repo_url"]),
                "commit_url": "",
                "commit_id": e["commit"],
                "method_name": sig,        # used by run_simulation_primevul.py
                "target_method": sig,      # used by run_llm_reasoning.py
                "target_code": vuln_fn,
                "CWE_id": cwe,
                "CVE_id": e["cve_id"] if "cve_id" in e else clean.get("cve_id", ""),
                "is_vulnerable": True,
                "need_head_slicing": True,
                "target_api_name": [],
            })

    if args.extract_api and rows:
        print(f"Extracting sensitive APIs for {len(rows)} rows via OpenRouter ...", flush=True)

        def _one(row):
            try:
                apis = extract_api(row["target_code"], row["CVE_id"], row["CWE_id"])
            except Exception as ex:
                print(f"  api-extract fail {row['slug']}: {ex}", flush=True)
                apis = []
            row["target_api_name"] = apis
            row["need_head_slicing"] = not bool(apis)
            return row["slug"], len(apis)

        with ThreadPoolExecutor(max_workers=args.api_workers) as ex:
            for fut in as_completed([ex.submit(_one, r) for r in rows]):
                slug, k = fut.result()
                print(f"  {slug}: {k} apis", flush=True)

    out_path = dataset_dir / f"{args.tag}_{args.variant}.json"
    out_path.write_text(json.dumps(rows, indent=4, ensure_ascii=False))
    print(f"\nWrote {len(rows)} rows -> {out_path}", flush=True)
    if splice_fail:
        print(f"SPLICE FAILURES ({len(splice_fail)}): {splice_fail}", flush=True)
    print(f"target_project dirs: {len(by_dir)} under {target_project}", flush=True)
    print("\nNext (Joern required):")
    ctx = f"{Path(args.target_project).parent}/context_{args.tag}"
    print(f"  export VULWEAVER_PRIMEVUL_JSON={out_path}")
    print(f"  export VULWEAVER_CACHE_DIR={ctx}")
    print(f"  export VULWEAVER_TARGET_PROJECT={args.target_project}")
    print("  (then run run_simulation_primevul.py + run_llm_reasoning.py)")


if __name__ == "__main__":
    main()
