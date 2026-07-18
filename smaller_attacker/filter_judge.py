#!/usr/bin/env python3
"""
filter_judge.py — combine cvebench/judge_cve_new.py's LLM-judge verdict with
cvebench/patch_and_test.py's build/test verdict into the final "good" slug
list: samples that (a) build and pass the real test suite, AND (b) an LLM
judge confirms are not broken and genuinely contain the intended NPD.

cvebench/build_benchmark.py only filters on (b) (judge verdict == "vulnerable")
— it doesn't know about the build/test result at all. This script produces a
judge jsonl pre-filtered on both conditions, so build_benchmark.py (used
unmodified) only ever sees samples that also passed (a).

Each judge row already records which round (r1, r2, ...) judge_cve_new.py's
own find_best_output() picked for that slug (its priority: pass > partial >
any) — so we just re-check verdict==pass for THAT SAME round's
attacker_result.json, per-pid, instead of re-deriving "best round" ourselves.

Usage:
  python3 smaller_attacker/filter_judge.py \\
      --judge       smaller_attacker/results/<tag>/phase1/judge.jsonl \\
      --rounds-dir  smaller_attacker/results/<tag>/phase1/rounds \\
      --out         smaller_attacker/results/<tag>/phase1/judge_filtered.jsonl \\
      --good-slugs  smaller_attacker/results/<tag>/phase1/good_slugs.txt
"""
import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", required=True)
    ap.add_argument("--rounds-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--good-slugs", required=True)
    args = ap.parse_args()

    judge_rows = [json.loads(l) for l in Path(args.judge).read_text().splitlines() if l.strip()]
    rounds_dir = Path(args.rounds_dir)

    good = []
    for row in judge_rows:
        pid = row["pilot_id"]
        rnd = row.get("round", "")
        result_path = rounds_dir / rnd / pid / "attacker_result.json"
        build_ok = False
        if result_path.exists():
            br = json.loads(result_path.read_text())
            build_ok = br.get("status") == "ok" and br.get("verdict") == "pass"
        if row.get("verdict") == "vulnerable" and build_ok:
            good.append(row)

    Path(args.out).write_text("\n".join(json.dumps(r) for r in good) + ("\n" if good else ""))
    Path(args.good_slugs).write_text("\n".join(r["pilot_id"] for r in good) + ("\n" if good else ""))

    print(f"Judge rows:        {len(judge_rows)}")
    print(f"judge=vulnerable & build/test=pass: {len(good)}")
    print(f"Wrote {args.out}")
    print(f"Wrote {args.good_slugs}")


if __name__ == "__main__":
    main()
