#!/usr/bin/env python3
"""
score_phase2_tables.py — two clean tables across all detectors for a model
tag, using score_phase2.score_one() for the underlying parsing (same
baseline_miss / TP_clean handling, same whitelist-by-good_slugs.txt safety).

Table 1 — slug-level ASR per detector: how many TP_clean slugs were flipped
by AT LEAST ONE attack type (not per-attempt/per-round).

Table 2 — per-attack-type breakdown per detector: how many TP_clean slugs
each individual attack type flipped (out of TP_clean — every type runs to
completion on every TP_clean slug here since --stop-on-any-flip was not
used, so this is directly comparable to Table 1's denominator).

Usage:
  python3 smaller_attacker/score_phase2_tables.py [--tag gemma4-26b-a4b]
                                                    [--detectors vulnllmr openvul vultrial vulrag]
                                                    [--run-tag pilot_v1]
"""
import argparse
from pathlib import Path

from score_phase2 import score_one

HERE = Path(__file__).parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="gemma4-26b-a4b")
    ap.add_argument("--detectors", nargs="+", default=["vulnllmr", "openvul", "vultrial", "vulrag"])
    ap.add_argument("--run-tag", default="pilot_v1")
    args = ap.parse_args()

    results = {}
    for det in args.detectors:
        r = score_one(args.tag, args.run_tag, det)
        if r["status"] == "ok":
            results[det] = r

    print(f"=== {args.tag} ===\n")

    print("Table 1 — slug-level ASR (flipped by >=1 attack type)")
    print(f"{'detector':<12} {'flipped':>8} {'tp_clean':>9} {'slug_ASR':>9}")
    for det in args.detectors:
        r = results.get(det)
        if r is None:
            print(f"{det:<12}  (not run)")
            continue
        print(f"{det:<12} {r['slugs_flipped']:>8} {r['tp_clean']:>9} {r['slug_asr']:>8.1%}")

    print("\nTable 2 — per-attack-type breakdown (flipped / tp_clean)")
    all_types = sorted({t for r in results.values() for t in r["by_type"]})
    header = f"{'attack_type':<15}" + "".join(f"{det:>14}" for det in args.detectors)
    print(header)
    for atype in all_types:
        row = f"{atype:<15}"
        for det in args.detectors:
            r = results.get(det)
            if r is None or atype not in r["by_type"]:
                row += f"{'--':>14}"
                continue
            c = r["by_type"][atype]
            tp = r["tp_clean"]
            asr = (c["flipped"] / tp) if tp else 0.0
            row += f"{c['flipped']:>3}/{tp:<3} ({asr:>4.0%})".rjust(14)
        print(row)


if __name__ == "__main__":
    main()
