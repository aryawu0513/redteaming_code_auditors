#!/usr/bin/env python3
"""
compare_fromscratch_cvebench.py

Side-by-side comparison of the original CVE bench adaptive attack results
(system-blind seeds) vs. the from-scratch adaptive attack results
(system-aware seeds bootstrapped from the detector's own reasoning).

Old results:   attacker/adaptive/results/vulnllmr/     (CVE slugs only)
               attacker/adaptive/results/openvul/
New results:   attacker/adaptive/results/vulnllmr_fromscratch/
               attacker/adaptive/results/openvul_fromscratch/

Usage:
    python scripts/oneoff/compare_fromscratch_cvebench.py
"""

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
RESULTS_DIR = REPO_ROOT / "attacker" / "adaptive" / "results"
sys.path.insert(0, str(REPO_ROOT / "attacker" / "adaptive"))

from summarize_results import flip_round, is_baseline_miss  # noqa: E402

ALL_TYPES = [
    "COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer",
]
MAX_BUDGET = 5

CVE_SLUGS = [
    "NPD-CVE-01", "NPD-CVE-02", "NPD-CVE-03", "NPD-CVE-04",
    "NPD-CVE-06", "NPD-CVE-07", "NPD-CVE-08", "NPD-CVE-10",
]


def collect_slug_stats(system_dir: pathlib.Path, slug: str) -> dict:
    """
    Returns a dict with keys:
        baseline_miss (bool)
        flipped (int)
        total (int)
        round_counts (dict[int, int])
        type_results (dict[str, int|None])  — round flipped or None
        missing_types (list[str])           — types with no dir at all
    """
    repo_dir = system_dir / f"repository_{slug}"
    if not repo_dir.exists():
        return {"exists": False}

    if is_baseline_miss(repo_dir):
        return {"exists": True, "baseline_miss": True}

    type_dirs: dict[str, pathlib.Path] = {}
    for d in repo_dir.iterdir():
        if d.is_dir() and d.name.startswith("adaptive_"):
            parts = d.name.split("_", 1)[1]
            for at in ALL_TYPES:
                if parts == at or parts.startswith(at + "_"):
                    type_dirs[at] = d
                    break

    round_counts: dict[int, int] = {r: 0 for r in range(MAX_BUDGET + 1)}
    type_results: dict[str, int | None] = {}
    for at in ALL_TYPES:
        if at not in type_dirs:
            type_results[at] = "missing"
            continue
        rnd = flip_round(type_dirs[at])
        type_results[at] = rnd
        if rnd is not None:
            round_counts[rnd] += 1

    flipped = sum(1 for v in type_results.values() if isinstance(v, int))
    total = sum(1 for v in type_results.values() if v != "missing")
    missing = [at for at, v in type_results.items() if v == "missing"]

    return {
        "exists": True,
        "baseline_miss": False,
        "flipped": flipped,
        "total": total,
        "round_counts": round_counts,
        "type_results": type_results,
        "missing_types": missing,
    }


def fmt_round_counts(rc: dict) -> str:
    parts = [f"r{r}:{rc[r]}" for r in range(MAX_BUDGET + 1) if rc.get(r, 0) > 0]
    return "  ".join(parts) if parts else "—"


def compare_system(system_old: str, system_new: str, label: str) -> None:
    old_dir = RESULTS_DIR / system_old
    new_dir = RESULTS_DIR / system_new

    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  OLD: {system_old}   NEW: {system_new}")
    print(f"{'='*70}")

    old_total_f, old_total_t = 0, 0
    new_total_f, new_total_t = 0, 0
    old_round_totals: dict[int, int] = {r: 0 for r in range(MAX_BUDGET + 1)}
    new_round_totals: dict[int, int] = {r: 0 for r in range(MAX_BUDGET + 1)}

    for slug in CVE_SLUGS:
        old = collect_slug_stats(old_dir, slug)
        new = collect_slug_stats(new_dir, slug)

        # Determine display status for each side
        def side_str(s: dict) -> str:
            if not s.get("exists"):
                return "no results"
            if s.get("baseline_miss"):
                return "baseline_miss"
            rc = fmt_round_counts(s["round_counts"])
            warn = f"  [{len(s['missing_types'])} types missing]" if s["missing_types"] else ""
            return f"{s['flipped']}/{s['total']}  [{rc}]{warn}"

        old_s = side_str(old)
        new_s = side_str(new)

        delta = ""
        if (old.get("exists") and not old.get("baseline_miss") and
                new.get("exists") and not new.get("baseline_miss")):
            diff = new["flipped"] - old["flipped"]
            if diff > 0:
                delta = f"  (+{diff})"
            elif diff < 0:
                delta = f"  ({diff})"
            else:
                delta = "  (=)"

        print(f"\n  {slug}")
        print(f"    old: {old_s}")
        print(f"    new: {new_s}{delta}")

        # Accumulate totals (skip baseline_miss and no-results)
        if old.get("exists") and not old.get("baseline_miss"):
            old_total_f += old["flipped"]
            old_total_t += old["total"]
            for r, v in old["round_counts"].items():
                old_round_totals[r] += v
        if new.get("exists") and not new.get("baseline_miss"):
            new_total_f += new["flipped"]
            new_total_t += new["total"]
            for r, v in new["round_counts"].items():
                new_round_totals[r] += v

    old_pct = f"{100*old_total_f/old_total_t:.1f}%" if old_total_t else "n/a"
    new_pct = f"{100*new_total_f/new_total_t:.1f}%" if new_total_t else "n/a"
    diff_f = new_total_f - old_total_f

    print(f"\n  {'─'*50}")
    print(f"  OVERALL  old: {old_total_f}/{old_total_t} ({old_pct})  [{fmt_round_counts(old_round_totals)}]")
    print(f"  OVERALL  new: {new_total_f}/{new_total_t} ({new_pct})  [{fmt_round_counts(new_round_totals)}]")
    sign = "+" if diff_f >= 0 else ""
    print(f"  DELTA: {sign}{diff_f} flips  ({sign}{diff_f}/{old_total_t if old_total_t else '?'})")


def main() -> None:
    compare_system("vulnllm",   "vulnllmr_fromscratch",  "VulnLLM-R")
    compare_system("openvul",   "openvul_fromscratch",   "OpenVul")
    print()


if __name__ == "__main__":
    main()
