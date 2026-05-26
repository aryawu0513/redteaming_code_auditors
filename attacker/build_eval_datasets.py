#!/usr/bin/env python3
"""
build_eval_datasets.py — Convert attacker solution.c files into the unified benchmark
JSON format consumed by VulnLLM-R, VulTrial, OpenVul, and RepoAudit.

For each repository_SLUG, reads solution.c (clean) and solution_ATTACK.c files,
splits each into context (helper functions) + target_function (main), and writes:

  benchmark/leetcodebench_gpt54mini/baseline/repository_SLUG/SLUG_CLEAN.json
  benchmark/leetcodebench_gpt54mini/context_aware/repository_SLUG/SLUG_COT.json
  ...

Also copies the matching .c file alongside the JSON.

Unified JSON schema: code, context, target_function, function_name, file_name,
  CWE_ID, RELATED_CWE, stack_trace, target, language, dataset, idx, slug, variant
"""

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_RUNS_DIR = Path(__file__).parent / "runs" / "gpt-5.4-mini"
DEFAULT_OUT_ROOT = REPO_ROOT / "benchmark" / "leetcodebench_gpt54mini"

ATTACK_VARIANTS = [
    "CLEAN",
    "COT", "FT", "CG",
    "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity",
]

MAIN_RE = re.compile(r'^(?:int|void)\s+main\s*\(', re.MULTILINE)


def split_file(code: str) -> tuple[str, str]:
    """Return (context, target_function) split at the start of main()."""
    m = MAIN_RE.search(code)
    if not m:
        raise ValueError("No main() found")
    return code[:m.start()].rstrip(), code[m.start():]


def build_entry(slug: str, variant: str, context: str, target: str, idx: int) -> dict:
    file_name = "solution.c" if variant == "CLEAN" else f"solution_{variant}.c"
    return {
        "code": f"// context\n{context}\n\n// target function\n{target}",
        "context": context,
        "target_function": target,
        "function_name": "main",
        "file_name": file_name,
        "CWE_ID": ["CWE-476"],
        "RELATED_CWE": [],
        "stack_trace": "",
        "target": 1,
        "language": "c",
        "dataset": "leetcodebench",
        "idx": idx,
        "slug": slug,
        "variant": variant,
    }


def load_verification(repo_dir: Path) -> dict[str, str]:
    """Return {attack_type: status} from verification.json, or {} if missing."""
    vpath = repo_dir / "verification.json"
    if not vpath.exists():
        return {}
    return json.load(vpath.open())


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR,
                        help=f"Dir containing repository_<slug>/ subdirs. Default: {DEFAULT_RUNS_DIR}")
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT,
                        help=f"Output root for {{baseline,context_aware}}/. Default: {DEFAULT_OUT_ROOT}")
    args = parser.parse_args()

    runs_dir = args.runs_dir
    out_root = args.out_root

    if not runs_dir.is_dir():
        print(f"ERROR: runs dir not found: {runs_dir}", file=sys.stderr)
        sys.exit(1)

    slugs = sorted(p.name.removeprefix("repository_")
                   for p in runs_dir.iterdir()
                   if p.is_dir() and p.name.startswith("repository_"))

    total = 0
    for slug in slugs:
        repo_dir = runs_dir / f"repository_{slug}"

        verification = load_verification(repo_dir)
        ok_attacks = {at for at in ATTACK_VARIANTS[1:] if verification.get(at) == "ok"}
        if not ok_attacks:
            print(f"  [skip] {slug} — no verified attack variants")
            continue

        for idx, variant in enumerate(ATTACK_VARIANTS):
            src = repo_dir / ("solution.c" if variant == "CLEAN" else f"solution_{variant}.c")
            if not src.exists():
                print(f"  [skip] {slug}/{variant} — file not found")
                continue
            if variant != "CLEAN" and verification.get(variant) != "ok":
                print(f"  [skip] {slug}/{variant} — verification={verification.get(variant)!r}")
                continue

            category = "baseline" if variant == "CLEAN" else "context_aware"
            out_dir  = out_root / category / f"repository_{slug}"
            out_dir.mkdir(parents=True, exist_ok=True)

            try:
                context, target = split_file(src.read_text())
            except ValueError as e:
                print(f"  [skip] {slug}/{variant} — {e}")
                continue

            entry = build_entry(slug, variant, context, target, idx)
            out_json = out_dir / f"{slug}_{variant}.json"
            out_json.write_text(json.dumps([entry], indent=2))
            shutil.copy2(src, out_dir / src.name)
            total += 1

        print(f"  {slug}: written to {out_root}/{{baseline,context_aware}}/repository_{slug}/")

    print(f"\nDone — {total} JSON files written under {out_root}")


if __name__ == "__main__":
    main()
