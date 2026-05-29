#!/usr/bin/env python3
"""
build_eval_datasets_sofa.py — Convert sofa-pbrpc attacker solution.cc files into the
unified benchmark JSON format consumed by VulnLLM-R, OpenVul, and RepoAudit.

Differences from build_eval_datasets.py (leetcode C variant):
  - Files are .cc (C++), language = "cpp"
  - Target function is NOT main() — it is read from line 1 of problem.md:
      "# Task: <function_name>"
  - Split regex matches the exact function signature in the .cc file
  - dataset tag = "sofa-pbrpc-npd"

Outputs:
  benchmark/sofa_qwen3_27b/baseline/repository_NPD-N/NPD-N_CLEAN.json
  benchmark/sofa_qwen3_27b/context_aware/repository_NPD-N/NPD-N_COT.json
  ...

Usage:
  python attacker/build_eval_datasets_sofa.py \\
      --runs-dir attacker/runs/qwen3.6-27b \\
      --out-root benchmark/sofa_qwen3_27b
"""

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_RUNS_DIR = Path(__file__).parent / "runs" / "qwen3.6-27b"
DEFAULT_OUT_ROOT = REPO_ROOT / "benchmark" / "sofa_qwen3_27b"

ATTACK_VARIANTS = [
    "CLEAN",
    "COT", "FT", "CG",
    "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity",
]


def read_target_function_name(repo_dir: Path) -> str:
    """Extract function name from '# Task: <name>' in problem.md."""
    pm = repo_dir / "problem.md"
    if not pm.exists():
        raise ValueError(f"problem.md not found in {repo_dir}")
    first_line = pm.read_text().splitlines()[0]
    m = re.match(r"#\s*Task:\s*(\w+)", first_line)
    if not m:
        raise ValueError(f"Cannot parse function name from: {first_line!r}")
    return m.group(1)


def split_file(code: str, func_name: str) -> tuple[str, str]:
    """Return (context, target_function) by splitting before func_name's definition."""
    # Match C++ function definitions: return_type ... func_name(...)
    # The function is defined at a non-indented line (top-level), so we look for
    # lines where func_name( appears after optional return type / static / inline keywords.
    pattern = re.compile(
        r'^(?:(?:static|inline|explicit|virtual|override)\s+)*'
        r'(?:\w[\w\s:*&<>]*?\s+)?' + re.escape(func_name) + r'\s*\(',
        re.MULTILINE,
    )
    m = pattern.search(code)
    if not m:
        raise ValueError(f"Function definition for '{func_name}' not found")
    return code[:m.start()].rstrip(), code[m.start():]


def build_entry(slug: str, variant: str, func_name: str,
                context: str, target: str, idx: int) -> dict:
    ext = "cc"
    file_name = f"solution.{ext}" if variant == "CLEAN" else f"solution_{variant}.{ext}"
    return {
        "code": f"// context\n{context}\n\n// target function\n{target}",
        "context": context,
        "target_function": target,
        "function_name": func_name,
        "file_name": file_name,
        "CWE_ID": ["CWE-476"],
        "RELATED_CWE": [],
        "stack_trace": "",
        "target": 1,
        "language": "cpp",
        "dataset": "sofa-pbrpc-npd",
        "idx": idx,
        "slug": slug,
        "variant": variant,
    }


def load_verification(repo_dir: Path) -> dict[str, str]:
    vpath = repo_dir / "verification.json"
    if not vpath.exists():
        return {}
    return json.load(vpath.open())


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR,
                        help=f"Dir containing repository_NPD-N/ subdirs. Default: {DEFAULT_RUNS_DIR}")
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT,
                        help=f"Output root. Default: {DEFAULT_OUT_ROOT}")
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

        try:
            func_name = read_target_function_name(repo_dir)
        except ValueError as e:
            print(f"  [skip] {slug} — {e}")
            continue

        verification = load_verification(repo_dir)
        ok_attacks = {at for at in ATTACK_VARIANTS[1:] if verification.get(at) == "ok"}
        if not ok_attacks and not (repo_dir / "solution.cc").exists():
            print(f"  [skip] {slug} — no verified attack variants and no solution.cc")
            continue

        for idx, variant in enumerate(ATTACK_VARIANTS):
            src = repo_dir / ("solution.cc" if variant == "CLEAN" else f"solution_{variant}.cc")
            if not src.exists():
                print(f"  [skip] {slug}/{variant} — file not found")
                continue
            if variant != "CLEAN" and verification.get(variant) != "ok":
                status = verification.get(variant, "missing")
                print(f"  [skip] {slug}/{variant} — verification={status!r}")
                continue

            category = "baseline" if variant == "CLEAN" else "context_aware"
            out_dir = out_root / category / f"repository_{slug}"
            out_dir.mkdir(parents=True, exist_ok=True)

            try:
                context, target = split_file(src.read_text(), func_name)
            except ValueError as e:
                print(f"  [skip] {slug}/{variant} — {e}")
                continue

            entry = build_entry(slug, variant, func_name, context, target, idx)
            out_json = out_dir / f"{slug}_{variant}.json"
            out_json.write_text(json.dumps([entry], indent=2))
            shutil.copy2(src, out_dir / src.name)
            total += 1

        print(f"  {slug}: target={func_name}, "
              f"written to {out_root}/{{baseline,context_aware}}/repository_{slug}/")

    print(f"\nDone — {total} JSON files written under {out_root}")


if __name__ == "__main__":
    main()
