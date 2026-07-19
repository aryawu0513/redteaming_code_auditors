#!/usr/bin/env python3
"""
table_gen_latency.py — computes Table (\\label{tab:gen-latency-round} in
writing_overleaf/main.tex): mean attacker (Qwen refiner) generation time
per round, isolated from detector latency.

CAVEAT: adaptive_attacker/gen_timing.jsonl is a single, unscoped, growing
log with no per-run identifier or timestamp field — every refine_loop_
fromscratch.py invocation across the whole project appends to it. By the
time this script was written, the file had accumulated entries from all
the later informal-type-extension and D1/D2/D5 defense work done this
session, not just the original D0 attack-effectiveness run the table
describes (which used longer, more context-heavy prompts as prior_attempts
accumulated, and the informal-type/defense runs add their own overhead on
top). Computed means here run consistently ~15-30s higher per round than
the table's published values as a result. This script reports what's
computable from current data; it is NOT a faithful reproduction of the
original table without either a fresh isolated timing run or a scoped
subset of the log (not available — no timestamp/run-tag field to filter on).

Usage:
    python3 result_analysis/table_scripts/table_gen_latency.py
"""
import json
import os
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TIMING_LOG = os.path.join(REPO_ROOT, "adaptive_attacker/gen_timing.jsonl")


def main():
    sums = defaultdict(lambda: [0.0, 0])
    with open(TIMING_LOG) as f:
        for line in f:
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not d.get("success"):
                continue
            r = d.get("round")
            sums[r][0] += d["elapsed_sec"]
            sums[r][1] += 1

    print("WARNING: gen_timing.jsonl is unscoped — see module docstring. "
          "These numbers include timing from work done after the original "
          "table was generated and will read higher than the paper's values.\n")
    print(f"{'Round':<10}{'mean (s)':>10}{'n':>10}")
    for r in sorted(sums, key=lambda x: (x is None, x)):
        total, n = sums[r]
        label = "0 (bootstrap)" if r == 0 else str(r)
        print(f"{label:<10}{total/n:>10.1f}{n:>10}")


if __name__ == "__main__":
    main()
