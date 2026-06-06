#!/usr/bin/env python3
"""
Compute the three paper robustness metrics (arxiv 2602.00305) on adaptive
from-scratch attack results.

Metrics:
  ASRcond(k)  fraction of TP_clean flipped by attack variant k
  CR          fraction of TP_clean that resist ALL variants
  ΔTPR        absolute recall drop across full dataset (incl. baseline misses)

Usage:
    python result_analysis/paper_metrics.py
    python result_analysis/paper_metrics.py --systems openvul_fromscratch vulnllmr_fromscratch
    python result_analysis/paper_metrics.py --results-dir attacker/adaptive/results
"""

import argparse
import pathlib
import sys

# Allow running from repo root without installing as a package
sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from result_analysis.metrics import (
    ALL_TYPES,
    collect_system_results,
    compute_asr_cond,
    compute_cr,
    compute_delta_tpr,
)

REPO_ROOT    = pathlib.Path(__file__).parents[1]
RESULTS_DIR  = REPO_ROOT / "attacker" / "adaptive" / "results"
DEFAULT_SYSTEMS = ["openvul_fromscratch", "vulnllmr_fromscratch"]


def print_system(system: str, system_dir: pathlib.Path) -> None:
    if not system_dir.exists():
        print(f"\n[{system}] directory not found: {system_dir}")
        return

    repo_results = collect_system_results(system_dir)
    if not repo_results:
        print(f"\n[{system}] no repository_* dirs found")
        return

    asr  = compute_asr_cond(repo_results)
    cr   = compute_cr(repo_results)
    dtpr = compute_delta_tpr(repo_results)

    n_tp    = asr["tp_clean"]
    n_total = dtpr["n_total"]
    n_miss  = n_total - n_tp

    print(f"\n{'='*62}")
    print(f"  {system.upper()}   (N={n_total}, TP_clean={n_tp}, baseline_miss={n_miss})")
    print(f"{'='*62}")

    # ── ASRcond per variant ───────────────────────────────────────────────────
    print(f"\n  ASRcond  (|Flip(k)| / |TP_clean|={n_tp})")
    col = max(len(v) for v in ALL_TYPES)
    for v in ALL_TYPES:
        d = asr["per_variant"][v]
        bar = "#" * d["flipped"] + "-" * (n_tp - d["flipped"])
        print(f"    {v:<{col}}  {d['flipped']:>2}/{n_tp}  {d['asr']:.3f}  [{bar}]")
    best = asr["best"]
    print(f"    {'BEST (any variant)':<{col}}  {best['flipped']:>2}/{n_tp}  {best['asr']:.3f}")

    # ── CR ───────────────────────────────────────────────────────────────────
    print(f"\n  CR  (resists ALL {len(ALL_TYPES)} variants)")
    bar = "#" * cr["resistant"] + "-" * (n_tp - cr["resistant"])
    print(f"    {cr['resistant']:>2}/{n_tp}  {cr['cr']:.3f}  [{bar}]")

    # ── ΔTPR ─────────────────────────────────────────────────────────────────
    print(f"\n  ΔTPR  (recall drop = |Flip_union| / N={n_total})")
    bar = "#" * dtpr["flipped"] + "-" * (n_total - dtpr["flipped"])
    print(f"    {dtpr['flipped']:>2}/{n_total}  {dtpr['delta_tpr']:.3f}  [{bar}]")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--systems", nargs="+", default=DEFAULT_SYSTEMS,
                    help="System subdirectory names under --results-dir")
    ap.add_argument("--results-dir", type=pathlib.Path, default=RESULTS_DIR,
                    help=f"Root results directory (default: {RESULTS_DIR})")
    args = ap.parse_args()

    for system in args.systems:
        print_system(system, args.results_dir / system)
    print()


if __name__ == "__main__":
    main()
