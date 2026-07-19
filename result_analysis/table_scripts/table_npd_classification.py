#!/usr/bin/env python3
"""
table_npd_classification.py — computes Table (\\label{tab:npd} in
writing_overleaf/main.tex): the 125 injected NPD bugs by null-source
category, with static-analysis tool (CppCheck, Infer, CodeQL) recall.

This is a thin join over two existing, already-run pipelines — does not
reclassify or rerun static analyzers itself:
  - result_analysis/static_analyzer/classify_npd_bugs.py (source_kind per slug)
  - result_analysis/static_analyzer/sa_merge_results.py (per-tool hit flags)
both of which write into the same npd_classification.json (run them first,
in that order, if it's stale/missing).

Usage:
    python3 result_analysis/static_analyzer/classify_npd_bugs.py
    python3 result_analysis/static_analyzer/sa_merge_results.py
    python3 result_analysis/table_scripts/table_npd_classification.py
"""
import json
import os
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH = os.path.join(REPO_ROOT, "result_analysis/static_analyzer/npd_classification.json")

CATEGORY_ORDER = ["null_literal", "stdlib_alloc", "stdlib_other", "callee_return",
                   "output_param", "struct_field", "param_in", "custom_alloc"]


def main():
    data = json.load(open(DATA_PATH))
    by_cat = defaultdict(lambda: {"n": 0, "det": 0})
    for row in data:
        cat = row.get("source_kind")
        by_cat[cat]["n"] += 1
        if row.get("any_sa_hit"):
            by_cat[cat]["det"] += 1

    total_n = total_det = 0
    print(f"{'Category':<16}{'Det/N':>10}")
    for cat in CATEGORY_ORDER:
        s = by_cat.get(cat, {"n": 0, "det": 0})
        total_n += s["n"]
        total_det += s["det"]
        print(f"{cat:<16}{s['det']:>4}/{s['n']:<5}")
    print(f"{'Total':<16}{total_det:>4}/{total_n:<5}")


if __name__ == "__main__":
    main()
