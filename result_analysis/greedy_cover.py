#!/usr/bin/env python3
"""
greedy_cover.py

Greedy set-cover over attack types, measuring which types are needed to reach
maximum flip coverage (b5 cap). Runs both joint (all systems summed) and
per-system to check consistency.

Usage:
    python result_analysis/greedy_cover.py
"""

import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

REPO_ROOT   = pathlib.Path(__file__).parents[1]
RESULTS_DIR = REPO_ROOT / "adaptive_attacker" / "results"

SYSTEMS = {
    "vulnllmr": "vulnllmr_funclevel_full",
    "openvul":  "openvul_full",
    "vultrial": "vultrial_full",
    "vulrag":   "vulrag_full",
}
SNAMES = list(SYSTEMS)

ALL_TYPES = [
    "COT", "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer", "CG",
    "AA_MSG", "AA_USR", "FT", "AA_CA",
]

INF   = 999
MAX_B = 5


def load_slug_flips(sys_dir: pathlib.Path) -> list[set]:
    flips = []
    for slug_dir in sorted(sys_dir.iterdir()):
        if not slug_dir.is_dir():
            continue
        f = set()
        for att_dir in slug_dir.iterdir():
            if not att_dir.is_dir() or not att_dir.name.startswith("adaptive_"):
                continue
            parts = att_dir.name[len("adaptive_"):]
            matched = next((t for t in ALL_TYPES if parts.startswith(t + "_")), None)
            if matched is None:
                continue
            rf = att_dir / "result.json"
            if not rf.exists():
                continue
            r = json.loads(rf.read_text())
            if r.get("final_verdict") == "safe" and r.get("rounds_used", INF) <= MAX_B:
                f.add(matched)
        flips.append(f)
    return flips


def greedy_cover(flips: list[set]) -> list[tuple[str, int, int]]:
    """Returns list of (type, marginal_gain, cumulative_covered)."""
    remaining = list(ALL_TYPES)
    covered: set[int] = set()
    order = []
    for _ in range(len(ALL_TYPES)):
        best_t, best_gain = None, -1
        for t in remaining:
            gain = sum(1 for i, f in enumerate(flips) if t in f and i not in covered)
            if gain > best_gain:
                best_gain, best_t = gain, t
        for i, f in enumerate(flips):
            if best_t in f:
                covered.add(i)
        remaining.remove(best_t)
        order.append((best_t, best_gain, len(covered)))
    return order


def print_cover(label: str, flips: list[set], order: list[tuple]) -> None:
    max_cov = sum(1 for f in flips if f)
    n = len(flips)
    print(f"=== {label}  (max attainable={max_cov}/{n}) ===")
    print(f"  {'Pick':<4}  {'Type':<16}  {'Marginal':>9}  {'Cumulative':>12}  {'% of max':>9}")
    for i, (t, gain, cum) in enumerate(order):
        pct = f"{100*cum/max_cov:.1f}%" if max_cov else "-"
        print(f"  {i+1:<4}  {t:<16}  {gain:>9}  {cum:>12}  {pct:>9}")
    print()


def main() -> None:
    all_flips: dict[str, list[set]] = {}
    for label, system in SYSTEMS.items():
        sys_dir = RESULTS_DIR / system
        if not sys_dir.exists():
            print(f"[warn] {sys_dir} not found, skipping", file=sys.stderr)
            continue
        all_flips[label] = load_slug_flips(sys_dir)

    # Joint greedy (all systems summed)
    joint = []
    for label, flips in all_flips.items():
        joint.extend(flips)
    print_cover("JOINT (all systems)", joint, greedy_cover(joint))

    # Per-system greedy
    for label, flips in all_flips.items():
        print_cover(label, flips, greedy_cover(flips))


if __name__ == "__main__":
    main()
