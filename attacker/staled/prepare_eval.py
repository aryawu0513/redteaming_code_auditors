"""
prepare_eval.py — Convert agent-generated solution_*.c files into inputs for
VulnLLM-R (JSON dataset) and RepoAudit (raw .c files in benchmark tree).

Usage:
    python attacker/prepare_eval.py --runs-dir attacker/runs/gpt-5.4-mini

Processes all repository_* dirs that have a verification.json with ok results.
After running, follow the printed commands to launch each evaluator.
"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACK_TYPES = ["COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA",
                "TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity"]


def find_solutions(repo_dir: str) -> dict[str, str]:
    """Return {attack_type: source_code} for solutions verified ok in verification.json."""
    vpath = os.path.join(repo_dir, "verification.json")
    if not os.path.isfile(vpath):
        return {}
    with open(vpath) as f:
        verification = json.load(f)

    solutions = {}
    skipped = []
    for at in ATTACK_TYPES:
        status = verification.get(at)
        if status != "ok":
            skipped.append(f"{at}({status})")
            continue
        path = os.path.join(repo_dir, f"solution_{at}.c")
        if not os.path.isfile(path):
            skipped.append(f"{at}(missing)")
            continue
        with open(path) as f:
            solutions[at] = f.read()
    if skipped:
        print(f"  Skipped: {', '.join(skipped)}")
    return solutions


def prepare_vulnllm(slug: str, solutions: dict[str, str]) -> str:
    """Write VulnLLM-R JSON datasets. Returns the dataset directory."""
    dataset_dir = os.path.join(
        REPO_ROOT, "VulnLLM-R", "datasets", "C", "NPD",
        "attacker", "context_aware", slug, "c",
    )
    os.makedirs(dataset_dir, exist_ok=True)

    for fname in os.listdir(dataset_dir):
        if not fname.endswith(".json"):
            continue
        at = fname.replace(f"{slug}_", "").replace(".json", "")
        if at not in solutions:
            os.remove(os.path.join(dataset_dir, fname))

    for idx, (at, code) in enumerate(solutions.items(), start=1):
        entry = {
            "CWE_ID": ["CWE-476"],
            "code": code,
            "target": 1,
            "language": "c",
            "dataset": "attacker",
            "idx": idx,
            "attack_type": at,
            "RELATED_CWE": [],
            "stack_trace": True,
        }
        out = os.path.join(dataset_dir, f"{slug}_{at}.json")
        with open(out, "w") as f:
            json.dump([entry], f, indent=2)

    print(f"  VulnLLM-R: {dataset_dir}  ({len(solutions)} files)")
    return os.path.dirname(dataset_dir)


def prepare_repoaudit(slug: str, solutions: dict[str, str]) -> str:
    """Copy .c files into RepoAudit benchmark tree. Returns the benchmark directory."""
    bench_dir = os.path.join(
        REPO_ROOT, "RepoAudit", "benchmark", "C", "NPD",
        "attacker", "context_aware", slug,
    )
    os.makedirs(bench_dir, exist_ok=True)

    for fname in os.listdir(bench_dir):
        if not fname.endswith(".c"):
            continue
        at = fname.replace(f"{slug}_", "").replace(".c", "")
        if at not in solutions:
            os.remove(os.path.join(bench_dir, fname))

    for at, code in solutions.items():
        dst = os.path.join(bench_dir, f"{slug}_{at}.c")
        with open(dst, "w") as f:
            f.write(code)

    print(f"  RepoAudit: {bench_dir}  ({len(solutions)} files)")
    return bench_dir


def print_commands(all_vl_dirs: list[str], all_ra_dirs: list[str]):
    # all_vl_dirs: list of parent-of-c dirs, e.g. .../attacker/context_aware/SLUG
    # VulnLLM-R needs each slug dir as a separate --dataset_path arg
    vl_slug_dirs = sorted(set(all_vl_dirs))
    # output_dir = replace /datasets/ with /results/ in common parent
    vl_output = os.path.abspath(os.path.commonpath(vl_slug_dirs)).replace("/datasets/", "/results/") if vl_slug_dirs else ""
    ra_parent = sorted(set(os.path.dirname(d) for d in all_ra_dirs))[0] if all_ra_dirs else ""

    print()
    print("=" * 70)
    print("Run VulnLLM-R  (requires GPU + UCSB-SURFI/VulnLLM-R-7B):")
    print("=" * 70)
    if vl_slug_dirs:
        dataset_args = " \\\n      ".join(os.path.abspath(d) for d in vl_slug_dirs)
        print(f"""\
cd {REPO_ROOT}
VLLM_USE_V1=0 CUDA_VISIBLE_DEVICES=<GPU_ID> .venv/bin/python -m vulscan.test.test \\
    --dataset_path \\
      {dataset_args} \\
    --language c \\
    --model UCSB-SURFI/VulnLLM-R-7B \\
    --use_cot --use_policy \\
    --vllm --tp 1 --max_tokens 4096 --save \\
    --output_dir {vl_output}
""")

    print("=" * 70)
    print("Run RepoAudit  (uses claude-sonnet-4-6, needs ANTHROPIC_API_KEY):")
    print("=" * 70)
    print(f"""\
cd {REPO_ROOT}/RepoAudit/src
MODEL=claude-sonnet-4-6 \\
LANGUAGE=Cpp \\
    bash run_repoaudit.sh \\
    {ra_parent} \\
    NPD \\
    "*.c"
""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-dir", default="attacker/runs/gpt-5.4-mini",
                        help="Directory containing repository_* subdirs")
    args = parser.parse_args()

    runs_dir = os.path.abspath(args.runs_dir)
    if not os.path.isdir(runs_dir):
        print(f"ERROR: not a directory: {runs_dir}", file=sys.stderr)
        sys.exit(1)

    all_vl_dirs, all_ra_dirs = [], []
    total_solutions = 0

    for entry in sorted(os.scandir(runs_dir), key=lambda e: e.name):
        if not entry.is_dir() or not entry.name.startswith("repository_"):
            continue
        slug = entry.name.replace("repository_", "")
        solutions = find_solutions(entry.path)
        if not solutions:
            print(f"{entry.name}: no verified solutions, skipping")
            continue
        print(f"{entry.name}: {len(solutions)} solutions")
        vl_dir = prepare_vulnllm(slug, solutions)
        ra_dir = prepare_repoaudit(slug, solutions)
        all_vl_dirs.append(vl_dir)
        all_ra_dirs.append(ra_dir)
        total_solutions += len(solutions)

    print(f"\nTotal: {total_solutions} verified solutions across {len(all_vl_dirs)} problems")
    if all_vl_dirs:
        print_commands(all_vl_dirs, all_ra_dirs)


if __name__ == "__main__":
    main()
