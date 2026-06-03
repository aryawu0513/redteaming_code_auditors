#!/usr/bin/env python3
"""
Summarize adaptive refinement results per system.

For each repo shows per-round flip counts (how many attack types flipped
at round 0, round 1, ..., budget) plus total. Also prints aggregate
per-round and overall stats.

Repos are split into three groups:
  - leetcodebench: repository_<hex>      (e.g. repository_069A7F404506)
  - sofa:          repository_NPD-[123]  (e.g. repository_NPD-1)
  - cvebench:      repository_NPD-CVE-*  (e.g. repository_NPD-CVE-01)

Repos where the system cannot achieve a baseline are excluded entirely.

Usage:
    python attacker/adaptive/summarize_results.py [--systems vulnllm openvul ...]
                                                  [--dataset leetcodebench sofa cvebench]
                                                  [--results-dir path/to/results]
"""
import argparse
import json
import pathlib

RESULTS_DIR = pathlib.Path(__file__).parent / "results"
ALL_TYPES = ["COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA",
             "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer"]
MAX_BUDGET = 5


def flip_round(type_dir: pathlib.Path) -> int | None:
    """
    Return the round at which this attack type flipped (0-indexed),
    or None if it never flipped.
    """
    result_file = type_dir / "result.json"
    if not result_file.exists():
        # Still in progress or never ran — check round_0.json
        r0 = type_dir / "round_0.json"
        if r0.exists():
            d = json.loads(r0.read_text())
            if d.get("detector_verdict") == "safe":
                return 0
        return None

    result = json.loads(result_file.read_text())
    if result.get("final_verdict") == "safe":
        if result.get("stop_reason") == "static_succeeded":
            return 0
        return result.get("rounds_used")
    return None


def is_baseline_miss(repo_dir: pathlib.Path) -> bool:
    summary_file = repo_dir / "phase1_summary_partial.json"
    if summary_file.exists():
        data = json.loads(summary_file.read_text())
        if len(data) == 1 and data[0].get("stop_reason") == "baseline_miss":
            return True
    return False


def dataset_of(slug: str) -> str:
    """Return 'cvebench', 'sofa', or 'leetcodebench' for a repo dir name."""
    if slug.startswith("repository_NPD-CVE-"):
        return "cvebench"
    if slug.startswith("repository_NPD-"):
        return "sofa"
    return "leetcodebench"


def print_group(label: str, repo_dirs: list[pathlib.Path]) -> tuple[int, int, int, dict]:
    """Print results for a group of repos. Returns (flipped, total, skipped, round_totals)."""
    round_totals: dict[int, int] = {r: 0 for r in range(MAX_BUDGET + 1)}
    grand_flipped = 0
    grand_total = 0
    skipped = 0

    print(f"\n  -- {label} --")

    for repo_dir in repo_dirs:
        slug = repo_dir.name

        if is_baseline_miss(repo_dir):
            skipped += 1
            print(f"    {slug}: baseline_miss (skipped)")
            continue

        # Find per-type subdirs (adaptive_<TYPE>_<run_tag>/)
        type_dirs: dict[str, pathlib.Path] = {}
        for d in repo_dir.iterdir():
            if d.is_dir() and d.name.startswith("adaptive_"):
                parts = d.name.split("_", 1)[1]  # strip leading "adaptive_"
                for at in ALL_TYPES:
                    if parts == at or parts.startswith(at + "_"):
                        type_dirs[at] = d
                        break

        if not type_dirs:
            print(f"    {slug}: no type dirs found")
            continue

        round_counts: dict[int, int] = {r: 0 for r in range(MAX_BUDGET + 1)}
        n_types = len(type_dirs)

        for at, td in sorted(type_dirs.items()):
            rnd = flip_round(td)
            if rnd is not None:
                round_counts[rnd] += 1
                round_totals[rnd] += 1
                grand_flipped += 1
            grand_total += 1

        total_flipped = sum(round_counts.values())
        per_round = "  ".join(
            f"r{r}:{round_counts[r]}" for r in range(MAX_BUDGET + 1) if round_counts[r] > 0
        )
        print(f"    {slug}: {total_flipped}/{n_types}  [{per_round}]")

    per_round_agg = "  ".join(
        f"r{r}:{round_totals[r]}" for r in range(MAX_BUDGET + 1) if round_totals[r] > 0
    )
    skip_note = f"  ({skipped} baseline-miss excluded)" if skipped else ""
    print(f"    SUBTOTAL: {grand_flipped}/{grand_total} flipped  [{per_round_agg}]{skip_note}")

    return grand_flipped, grand_total, skipped, round_totals


DATASET_LABELS = {
    "leetcodebench": "LeetCode Bench",
    "sofa":          "sofa-pbrpc",
    "cvebench":      "CVE Bench",
}


def summarize_system(system: str, results_dir: pathlib.Path,
                     datasets: list[str]) -> None:
    base = results_dir / system
    if not base.exists():
        print(f"[{system}] results dir not found: {base}")
        return

    all_repo_dirs = sorted(d for d in base.iterdir() if d.is_dir())

    print(f"\n{'='*60}")
    print(f"  {system.upper()}")
    print(f"{'='*60}")

    total_flipped = 0
    total_problems = 0
    total_skipped = 0
    combined_round_totals: dict[int, int] = {r: 0 for r in range(MAX_BUDGET + 1)}

    for ds in datasets:
        group_dirs = [d for d in all_repo_dirs if dataset_of(d.name) == ds]
        if not group_dirs:
            continue
        f, t, s, rt = print_group(DATASET_LABELS.get(ds, ds), group_dirs)
        total_flipped += f
        total_problems += t
        total_skipped += s
        for r, v in rt.items():
            combined_round_totals[r] += v

    per_round_agg = "  ".join(
        f"r{r}:{combined_round_totals[r]}" for r in range(MAX_BUDGET + 1)
        if combined_round_totals[r] > 0
    )
    skip_note = f"  ({total_skipped} baseline-miss excluded)" if total_skipped else ""
    print(f"\n  OVERALL: {total_flipped}/{total_problems} flipped  [{per_round_agg}]{skip_note}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--systems", nargs="+", default=["vulnllm", "openvul"])
    parser.add_argument("--dataset", nargs="+",
                        choices=["leetcodebench", "sofa", "cvebench"],
                        default=["leetcodebench", "sofa", "cvebench"],
                        help="Which dataset group(s) to show (default: all)")
    parser.add_argument("--results-dir", type=pathlib.Path, default=RESULTS_DIR)
    args = parser.parse_args()

    for system in args.systems:
        summarize_system(system, args.results_dir, args.dataset)
    print()


if __name__ == "__main__":
    main()
