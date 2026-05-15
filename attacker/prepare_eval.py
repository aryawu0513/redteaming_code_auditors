"""
prepare_eval.py — Convert agent-generated solution_*.cpp files into inputs for
VulnLLM-R (JSON dataset) and RepoAudit (raw .cpp files in benchmark tree).

Usage:
    python attacker/prepare_eval.py --repo-dir attacker/experiments/repository_XXXX

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
    """Return {attack_type: source_code} for all solution_*.cpp files present."""
    solutions = {}
    for at in ATTACK_TYPES:
        path = os.path.join(repo_dir, f"solution_{at}.cpp")
        if os.path.isfile(path):
            with open(path) as f:
                solutions[at] = f.read()
    return solutions


def prepare_vulnllm(slug: str, solutions: dict[str, str]) -> str:
    """Write VulnLLM-R JSON datasets. Returns the dataset directory."""
    dataset_dir = os.path.join(
        REPO_ROOT, "VulnLLM-R", "datasets", "C", "NPD",
        "attacker", "context_aware", slug, "c",
    )
    os.makedirs(dataset_dir, exist_ok=True)

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

    print(f"VulnLLM-R datasets written to: {dataset_dir}  ({len(solutions)} files)")
    return os.path.dirname(dataset_dir)  # .../attacker/context_aware/{slug}


def prepare_repoaudit(slug: str, solutions: dict[str, str]) -> str:
    """Copy .cpp files into RepoAudit benchmark tree. Returns the benchmark directory."""
    bench_dir = os.path.join(
        REPO_ROOT, "RepoAudit", "benchmark", "C", "NPD",
        "attacker", "context_aware", slug,
    )
    os.makedirs(bench_dir, exist_ok=True)

    for at, code in solutions.items():
        dst = os.path.join(bench_dir, f"{slug}_{at}.cpp")
        with open(dst, "w") as f:
            f.write(code)

    print(f"RepoAudit benchmark files written to: {bench_dir}  ({len(solutions)} files)")
    return bench_dir


def print_commands(slug: str, vulnllm_dataset_dir: str, repoaudit_bench_dir: str):
    abs_vl = os.path.abspath(vulnllm_dataset_dir)
    abs_output = os.path.join(REPO_ROOT, "VulnLLM-R", "results", "C", "NPD", "attacker", slug)

    print()
    print("=" * 70)
    print("Run VulnLLM-R  (requires GPU + UCSB-SURFI/VulnLLM-R-7B):")
    print("=" * 70)
    print(f"""\
cd {REPO_ROOT}
VLLM_USE_V1=0 CUDA_VISIBLE_DEVICES=<GPU_ID> .venv/bin/python -m vulscan.test.test \\
    --dataset_path {abs_vl} \\
    --language c \\
    --model UCSB-SURFI/VulnLLM-R-7B \\
    --use_cot --use_policy \\
    --vllm --tp 1 --max_tokens 4096 --save \\
    --output_dir {abs_output}
""")

    print("=" * 70)
    print("Run RepoAudit  (uses anthropic/claude-3-7-sonnet-20250219, needs ANTHROPIC_API_KEY):")
    print("=" * 70)
    print(f"""\
cd {REPO_ROOT}/RepoAudit/src
MODEL=anthropic/claude-3-7-sonnet-20250219 \\
LANGUAGE=Cpp \\
    bash run_repoaudit.sh \\
    {repoaudit_bench_dir} \\
    NPD \\
    "*.cpp"
""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", required=True,
                        help="Path to experiment directory, e.g. attacker/experiments/repository_XXXX")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo_dir)
    if not os.path.isdir(repo_dir):
        print(f"ERROR: not a directory: {repo_dir}", file=sys.stderr)
        sys.exit(1)

    slug = os.path.basename(repo_dir).replace("repository_", "")
    solutions = find_solutions(repo_dir)

    if not solutions:
        print(f"No solution_*.cpp files found in {repo_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(solutions)} solutions for slug {slug}: {', '.join(solutions)}")
    print()

    vl_dir = prepare_vulnllm(slug, solutions)
    ra_dir = prepare_repoaudit(slug, solutions)
    print_commands(slug, vl_dir, ra_dir)


if __name__ == "__main__":
    main()
