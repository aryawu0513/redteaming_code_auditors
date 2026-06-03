#!/usr/bin/env python3
"""
Set up attacker run directories for the CVE NPD benchmark.

Reads pilot10.jsonl and samples_cve/, and for each entry creates:
  attacker/runs/<model>/repository_<pilot_id>/
    problem.md   ← copy of task.md
    starter.cc   ← copy
    context.cc   ← copy (used by build.yaml compile command)
    tests.cc     ← copy
    build.yaml   ← generated (lang-aware single-TU compile command)

Usage:
  python3 repo_cve_dataset_mining/setup_cve_attacker_runs.py pilot10.jsonl [--model qwen3.6-27b]
  python3 repo_cve_dataset_mining/setup_cve_attacker_runs.py pilot10.jsonl [NPD-CVE-01 ...]
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

HERE        = Path(__file__).parent
REPO_ROOT   = HERE.parent
SAMPLES_DIR = HERE / "samples_cve"


def infer_lang(row: dict) -> str:
    lang = row.get("lang")
    if lang in ("c", "cpp"):
        return lang
    ext = Path(row.get("file_path", "")).suffix.lower()
    return "cpp" if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh") else "c"


def write_build_yaml(out_dir: Path, lang: str, pilot_id: str) -> None:
    compiler = "g++" if lang == "cpp" else "gcc"
    std      = "c++17" if lang == "cpp" else "c11"
    ext      = ".cc"   if lang == "cpp" else ".c"
    # Compile solution + tests as a single translation unit so static functions
    # defined in solution are callable from the test code.
    yaml_content = f"""\
language: {lang}
file_ext: {ext}

# Compile solution + tests as one translation unit.
# context.cc is NOT compiled separately — the agent writes solution.cc as a
# complete file (starter.cc with stub filled in), which already contains all
# helpers. We concatenate solution + tests so static functions are visible.
compile:
  command: >
    sh -c
    "cat {{solution}} {{test_driver}} > /tmp/combined_{pilot_id}{ext} &&
     {compiler} -std={std} -w /tmp/combined_{pilot_id}{ext} -o {{binary}} -lm"

test:
  kind: exit_code
  driver: ${{SITE_DIR}}/tests.cc
  timeout: 30

static_analysis:
  build_compiler: {compiler}
"""
    (out_dir / "build.yaml").write_text(yaml_content)


def setup_one(row: dict, runs_dir: Path, samples_dir: Path = SAMPLES_DIR) -> bool:
    pid     = row["pilot_id"]
    lang    = infer_lang(row)
    src_dir = samples_dir / pid
    out_dir = runs_dir / f"repository_{pid}"
    out_dir.mkdir(parents=True, exist_ok=True)

    missing = []
    for f in ("starter.cc", "context.cc", "tests.cc", "task.md"):
        if not (src_dir / f).exists():
            missing.append(f)

    if missing:
        print(f"  {pid}: SKIP — missing {missing}")
        return False

    # Strip the "## Functional tests" section from problem.md — it describes
    # what the tests do, which the attacker misreads as instructions to write
    # test code inside solution.cc. Tests are already in tests.cc.
    task_md = (src_dir / "task.md").read_text()
    import re as _re
    task_md = _re.sub(r'\n## Functional tests.*', '', task_md, flags=_re.DOTALL).rstrip()
    (out_dir / "problem.md").write_text(task_md)
    shutil.copy(src_dir / "starter.cc", out_dir / "starter.cc")
    shutil.copy(src_dir / "context.cc", out_dir / "context.cc")
    shutil.copy(src_dir / "tests.cc",   out_dir / "tests.cc")
    write_build_yaml(out_dir, lang, pid)

    fn   = row.get("func_name", "")
    repo = row.get("repo_url", "").replace("https://github.com/", "")
    print(f"  {pid}: OK  ({fn}  ·  {repo}  ·  lang={lang})")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="pilot10.jsonl (or any filtered JSONL)")
    ap.add_argument("ids",   nargs="*", help="Pilot IDs to set up (default: all)")
    ap.add_argument("--model", default="qwen3.6-27b",
                    help="Model name — used as the runs subdirectory (default: qwen3.6-27b)")
    ap.add_argument("--samples-dir", default=None,
                    help=f"samples_cve directory (default: {SAMPLES_DIR})")
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir) if args.samples_dir else SAMPLES_DIR

    runs_dir   = REPO_ROOT / "attacker" / "runs" / args.model
    jsonl_path = Path(args.jsonl)
    filter_ids = set(args.ids) if args.ids else None

    rows = [json.loads(l) for l in jsonl_path.read_text().splitlines() if l.strip()]
    if filter_ids:
        rows = [r for r in rows if r.get("pilot_id") in filter_ids]

    print(f"Setting up {len(rows)} CVE samples → {runs_dir}/\n")
    ok = sum(setup_one(row, runs_dir, samples_dir) for row in rows)
    print(f"\n{ok}/{len(rows)} directories ready")
    print(f"\nNext: bash scripts/run_attacker_cve.sh")


if __name__ == "__main__":
    main()
