#!/usr/bin/env python3
"""
Summarize adaptive refinement results per system.

For each repo shows per-round flip counts (how many attack types flipped
at round 0, round 1, ..., budget) plus total. Also prints aggregate
per-round and overall stats.

Usage:
    python attacker/adaptive/summarize_results.py [--systems vulnllm openvul ...]
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


def summarize_system(system: str, results_dir: pathlib.Path) -> None:
    base = results_dir / system
    if not base.exists():
        print(f"[{system}] results dir not found: {base}")
        return

    repo_dirs = sorted(base.iterdir())
    round_totals = {r: 0 for r in range(MAX_BUDGET + 1)}
    grand_flipped = 0
    grand_total = 0
    baseline_misses = []

    print(f"\n{'='*60}")
    print(f"  {system.upper()}  ({len(repo_dirs)} repos)")
    print(f"{'='*60}")

    for repo_dir in repo_dirs:
        if not repo_dir.is_dir():
            continue
        slug = repo_dir.name

        # Check for baseline miss
        summary_file = repo_dir / "phase1_summary_partial.json"
        if summary_file.exists():
            data = json.loads(summary_file.read_text())
            if len(data) == 1 and data[0].get("stop_reason") == "baseline_miss":
                baseline_misses.append(slug)
                print(f"  {slug}: BASELINE MISS")
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
            print(f"  {slug}: no type dirs found")
            continue

        round_counts = {r: 0 for r in range(MAX_BUDGET + 1)}
        never_flipped = []
        n_types = len(type_dirs)

        for at, td in sorted(type_dirs.items()):
            rnd = flip_round(td)
            if rnd is not None:
                round_counts[rnd] += 1
                round_totals[rnd] += 1
                grand_flipped += 1
            else:
                never_flipped.append(at)
            grand_total += 1

        total_flipped = sum(round_counts.values())
        per_round = "  ".join(
            f"r{r}:{round_counts[r]}" for r in range(MAX_BUDGET + 1) if round_counts[r] > 0
        )
        miss_str = f"  miss={never_flipped}" if never_flipped else ""
        print(f"  {slug}: {total_flipped}/{n_types}  [{per_round}]{miss_str}")

    per_round_agg = "  ".join(
        f"r{r}:{round_totals[r]}" for r in range(MAX_BUDGET + 1) if round_totals[r] > 0
    )
    print(f"\n  AGGREGATE: {grand_flipped}/{grand_total} flipped  [{per_round_agg}]"
          f"  |  {len(baseline_misses)} baseline miss(es)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--systems", nargs="+", default=["vulnllm", "openvul"])
    parser.add_argument("--results-dir", type=pathlib.Path, default=RESULTS_DIR)
    args = parser.parse_args()

    for system in args.systems:
        summarize_system(system, args.results_dir)
    print()


if __name__ == "__main__":
    main()
