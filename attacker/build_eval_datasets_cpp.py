#!/usr/bin/env python3
"""
build_eval_datasets_cpp.py — Convert C++ attacker solution.cc files into the
unified benchmark JSON format consumed by VulnLLM-R, OpenVul, and RepoAudit.

Works for any C++ repository mined with the sofa-style pipeline:
  - Files are .cc (C++), language = "cpp"
  - Target function name is read from line 1 of problem.md: "# Task: <function_name>"
  - Split regex matches the exact function signature in the .cc file
  - deref_line and caller are voted across all annotated variants and stamped into JSON

Usage:
  python attacker/build_eval_datasets_cpp.py \\
      --runs-dir attacker/runs/qwen3.6-27b \\
      --out-root benchmark/sofa_qwen3_27b \\
      --dataset sofa-pbrpc-npd
"""

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from annotation_utils import vote_anchor

REPO_ROOT = Path(__file__).parent.parent

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
    pattern = re.compile(
        r'^\s*'                          # allow leading indentation
        r'(?:(?:static|inline|explicit|virtual|override)\s+)*'
        r'(?:\w[\w\s:*&<>]*?\s+)?'      # optional return type
        r'(?:\w[\w:]*::)*'              # optional Class:: / Namespace:: qualifiers
        + re.escape(func_name) + r'\s*\(',
        re.MULTILINE,
    )
    m = pattern.search(code)
    if not m:
        raise ValueError(f"Function definition for '{func_name}' not found")
    return code[:m.start()].rstrip(), code[m.start():]


def build_entry(slug: str, variant: str, func_name: str,
                context: str, target: str, idx: int,
                dataset: str, deref_line: str = "", caller: str = "") -> dict:
    file_name = "solution.cc" if variant == "CLEAN" else f"solution_{variant}.cc"
    return {
        "code": f"// context\n{context}\n\n// target function\n{target}",
        "context": context,
        "target_function": target,
        "function_name": func_name,
        "deref_line": deref_line,
        "caller": caller,
        "file_name": file_name,
        "CWE_ID": ["CWE-476"],
        "RELATED_CWE": [],
        "stack_trace": "",
        "target": 1,
        "language": "cpp",
        "dataset": dataset,
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
    parser.add_argument("--runs-dir", type=Path, required=True,
                        help="Dir containing repository_<slug>/ subdirs")
    parser.add_argument("--out-root", type=Path, required=True,
                        help="Output root for {baseline,context_aware}/")
    parser.add_argument("--dataset", default="cpp-npd",
                        help="Dataset tag written into each JSON record (default: cpp-npd)")
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

        # Detect language from solution file extension
        if (repo_dir / "solution.cc").exists():
            lang, ext = "cpp", ".cc"
        elif (repo_dir / "solution.c").exists():
            lang, ext = "c", ".c"
        else:
            print(f"  [skip] {slug} — no solution.cc / solution.c")
            continue

        try:
            func_name = read_target_function_name(repo_dir)
        except ValueError as e:
            print(f"  [skip] {slug} — {e}")
            continue

        verification = load_verification(repo_dir)
        ok_attacks = {at for at in ATTACK_VARIANTS[1:] if verification.get(at) == "ok"}
        if not ok_attacks:
            print(f"  [skip] {slug} — no verified attack variants")
            continue

        # Vote deref_line across all annotated variants.
        target_functions = []
        for v in ATTACK_VARIANTS[1:]:
            src = repo_dir / f"solution_{v}{ext}"
            if src.exists():
                try:
                    _, tgt = split_file(src.read_text(), func_name)
                    target_functions.append(tgt)
                except ValueError:
                    pass
        deref_line = vote_anchor(target_functions) or ""

        slug_written = False
        for idx, variant in enumerate(ATTACK_VARIANTS):
            src = repo_dir / (f"solution{ext}" if variant == "CLEAN" else f"solution_{variant}{ext}")
            if not src.exists():
                print(f"  [skip] {slug}/{variant} — file not found")
                continue
            if variant != "CLEAN" and verification.get(variant) != "ok":
                print(f"  [skip] {slug}/{variant} — verification={verification.get(variant)!r}")
                continue

            category = "baseline" if variant == "CLEAN" else "context_aware"
            out_dir = out_root / category / f"repository_{slug}"
            out_dir.mkdir(parents=True, exist_ok=True)

            try:
                context, target = split_file(src.read_text(), func_name)
            except ValueError as e:
                print(f"  [skip] {slug}/{variant} — {e}")
                continue

            entry = build_entry(slug, variant, func_name, context, target, idx,
                                args.dataset, deref_line, func_name)
            entry["language"] = lang
            out_json = out_dir / f"{slug}_{variant}.json"
            out_json.write_text(json.dumps([entry], indent=2))
            shutil.copy2(src, out_dir / src.name)
            total += 1
            slug_written = True

        if slug_written:
            print(f"  {slug}: target={func_name!r}, deref_line={deref_line!r}, "
                  f"written to {out_root}/{{baseline,context_aware}}/repository_{slug}/")

    print(f"\nDone — {total} JSON files written under {out_root}")


if __name__ == "__main__":
    main()
