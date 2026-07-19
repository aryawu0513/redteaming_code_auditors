#!/usr/bin/env python3
"""
portfolio_tradeoff.py

Budget-vs-coverage tradeoff for a fixed attacker portfolio of annotation types,
measured on the refined fromscratch_v1 runs (per-type subdirs with round_*.json).

Portfolio (default): the 5-type TOOL+COT set
  {TOOL_ClangSA, TOOL_Coverity, TOOL_Frama, TOOL_Fuzzer, COT}

Coverage at round k = fraction of items where ANY portfolio type first flips the
detector (verdict->safe) by round <= k. A stop-on-flip attacker's worst-case
budget at round k is len(portfolio) * (k + 1) detector calls.

Outputs (next to this script): portfolio_tradeoff.csv, portfolio_tradeoff.png
"""

import argparse
import csv
import glob
import json
import os
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "adaptive_attacker" / "results"
SYS = {
    "vulnllmr": "vulnllmr_funclevel_full",
    "openvul":  "openvul_full",
    "vultrial": "vultrial_full",
    "vulrag":   "vulrag_full",
}
ALL_TYPES = ["AA_CA", "AA_MSG", "AA_USR", "CG", "COT", "FT",
             "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer"]
DEFAULT_PORTFOLIO = ["COT", "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer"]
MAX_ROUND = 5  # all systems ran to budget=5 (rounds 0-5: round 0 + 5 refinements)


def first_flip_round(slug_dir: str, atype: str) -> int | None:
    """Min round index whose detector_verdict == 'safe', else None (or absent)."""
    sub = glob.glob(os.path.join(slug_dir, f"adaptive_{atype}_*"))
    if not sub:
        return None
    rounds = {}
    for rf in glob.glob(os.path.join(sub[0], "round_*.json")):
        m = re.search(r"round_(\d+)", os.path.basename(rf))
        if not m:
            continue
        try:
            rounds[int(m.group(1))] = json.load(open(rf)).get("detector_verdict")
        except Exception:
            continue
    safe = [r for r, v in rounds.items() if v == "safe"]
    return min(safe) if safe else None


def is_tp_clean(slug_dir: str) -> bool:
    """True if the detector caught the bug on clean (unannotated) code."""
    for fname in ("baseline_gate_fromscratch_v1.json",):
        path = os.path.join(slug_dir, fname)
        if os.path.exists(path):
            try:
                return json.load(open(path)).get("verdict") == "vulnerable"
            except Exception:
                pass
    # fall back to any baseline_gate_*.json
    for path in glob.glob(os.path.join(slug_dir, "baseline_gate_*.json")):
        try:
            return json.load(open(path)).get("verdict") == "vulnerable"
        except Exception:
            pass
    return False


def detector_curve(sysdir: str, portfolio: list[str],
                   no_drop: bool = False) -> tuple[int, int, int, dict[int, int]]:
    """Returns (n_baseline_miss, n_dropped, tp_clean_n, {round: flip_count}).

    Denominator is TP_clean (slugs where detector caught the bug on clean code).

    Contamination drop (default, no_drop=False): exclude slugs where a
    non-portfolio type's first flip precedes the portfolio's first flip.
    Those slugs may have had their portfolio win accelerated by a non-portfolio
    winner already in the shared library.

    no_drop=True: include all TP_clean slugs; report the portfolio's authentic
    observed flip round regardless of library state.
    """
    other = [t for t in ALL_TYPES if t not in portfolio]
    slugs = sorted(glob.glob(f"{RESULTS / sysdir}/repository_*"))
    tp_slugs = [s for s in slugs if is_tp_clean(s)]
    min_p, dropped = [], []
    for s in tp_slugs:
        fp = [first_flip_round(s, t) for t in portfolio]
        fo = [first_flip_round(s, t) for t in other]
        fp = [x for x in fp if x is not None and x <= MAX_ROUND]
        fo = [x for x in fo if x is not None and x <= MAX_ROUND]
        mp = min(fp) if fp else None
        mo = min(fo) if fo else None
        is_dropped = (not no_drop) and (mp is not None and mo is not None and mo < mp)
        dropped.append(is_dropped)
        min_p.append(mp)
    n_miss = len(slugs) - len(tp_slugs)
    n_drop = sum(dropped)
    clean_n = len(tp_slugs) - n_drop
    cov = {k: sum(1 for i, x in enumerate(min_p)
                  if not dropped[i] and x is not None and x <= k)
           for k in range(MAX_ROUND + 1)}
    return n_miss, n_drop, clean_n, cov


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--portfolio", nargs="+", default=DEFAULT_PORTFOLIO,
                    help="attack types in the portfolio")
    ap.add_argument("--out", default=str(HERE / "portfolio_tradeoff"),
                    help="output path stem (.csv/.png appended)")
    ap.add_argument("--no-drop", action="store_true",
                    help="include all TP_clean slugs; report authentic portfolio "
                         "flip round without dropping library-contaminated items")
    args = ap.parse_args()

    portfolio = args.portfolio
    nseeds = len(portfolio)
    print(f"Portfolio ({nseeds} types): {', '.join(portfolio)}")
    print(f"Budget at round k = {nseeds} x (k+1); rounds 0..{MAX_ROUND}\n")

    rows = []
    fig, ax = plt.subplots(figsize=(7.5, 5))
    for det, sysdir in SYS.items():
        n_miss, n_drop, clean_n, cov = detector_curve(sysdir, portfolio,
                                                       no_drop=args.no_drop)
        budgets = [nseeds * (k + 1) for k in range(MAX_ROUND + 1)]
        pct = [100 * cov[k] / clean_n for k in range(MAX_ROUND + 1)]
        # stop plotting once coverage plateaus
        max_cov = max(cov.values())
        stop_k = next(k for k in range(MAX_ROUND + 1) if cov[k] == max_cov)
        drop_str = "no-drop" if args.no_drop else f"dropped={n_drop}"
        print(f"{det:9s} baseline_miss={n_miss:2d} {drop_str} n={clean_n}  "
              + "  ".join(f"r{k}({budgets[k]}):{pct[k]:.0f}%" for k in range(MAX_ROUND + 1)))
        ax.plot(budgets[:stop_k + 1], pct[:stop_k + 1], marker="o", label=f"{det} (n={clean_n})")
        for k in range(MAX_ROUND + 1):
            rows.append({"detector": det, "round": k, "budget": budgets[k],
                         "coverage_pct": round(pct[k], 1),
                         "flips": cov[k], "n": clean_n,
                         "baseline_miss": n_miss, "dropped": n_drop})

    ax.set_xlabel(f"budget (multiples of portfolio size = {nseeds} detector calls)")
    ax.set_ylabel("coverage: % of items flipped to 'safe'")
    ax.set_title(f"Attacker portfolio tradeoff: {'+'.join(portfolio)}".replace("TOOL_", ""))
    ax.set_ylim(0, 100)
    tick_positions = [nseeds * (k + 1) for k in range(MAX_ROUND + 1)]
    ax.set_xticks(tick_positions)
    ax.set_xticklabels([f"{k + 1}×" for k in range(MAX_ROUND + 1)])
    ax.grid(True, alpha=0.3)
    ax.legend()
    for k in range(MAX_ROUND + 1):
        ax.axvline(nseeds * (k + 1), color="gray", alpha=0.12)
    fig.tight_layout()

    csv_path, png_path = args.out + ".csv", args.out + ".png"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["detector", "round", "budget",
                                          "coverage_pct", "flips", "n",
                                          "baseline_miss", "dropped"])
        w.writeheader()
        w.writerows(rows)
    fig.savefig(png_path, dpi=150)
    print(f"\nWrote {csv_path}\nWrote {png_path}")


if __name__ == "__main__":
    main()
