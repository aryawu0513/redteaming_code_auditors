#!/usr/bin/env python3
"""
table_uaf_headline.py — computes Table (\\label{tab:uaf-headline} in
writing_overleaf/main.tex): UAF (CWE-416) attack effectiveness per detector
at budget 5, on the UAF N=70 judge-confirmed benchmark. Same TP_clean/ASR
methodology as table2_attackeffectiveness.py, but pointed at the UAF
benchmark results (adaptive_attacker_uaf/results/uaf_{base}, tag "uaf_v1"),
aggregating the 5 UAF-specific attack types: COT, TOOL_ASan, TOOL_Coverity,
TOOL_ClangSA, TOOL_Infer.

Usage:
    python3 result_analysis/table_scripts/table_uaf_headline.py
"""
import csv
import glob
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TAG = "uaf_v1"
JUDGE_CONFIRMED = os.path.join(REPO_ROOT, "cvebench/uaf_judge_confirmed.txt")

SYSTEMS = {
    "OpenVul":   "uaf_openvul_full",
    "VulnLLM-R": "uaf_vulnllmr_full",
    "VulRAG":    "uaf_vulrag_full",
    "VulTrial":  "uaf_vultrial_full",
}


def get_ground_truth_slugs(base):
    judge_confirmed = set(open(JUDGE_CONFIRMED).read().split())
    slugs = set()
    for rd in glob.glob(os.path.join(REPO_ROOT, "adaptive_attacker_uaf/results", base, "repository_UAF-CVE-*")):
        slug = os.path.basename(rd).replace("repository_", "")
        if slug not in judge_confirmed:
            continue
        f = os.path.join(rd, f"baseline_gate_{TAG}.json")
        if not os.path.exists(f):
            continue
        try:
            if json.loads(open(f).read()).get("verdict") == "vulnerable":
                slugs.add(slug)
        except Exception:
            pass
    return slugs


def main():
    print(f"{'Detector':<10} {'TP_clean':>9} {'Flipped':>8} {'ASR':>8}")
    for name, base in SYSTEMS.items():
        gt = get_ground_truth_slugs(base)
        flipped = set()
        for slug in gt:
            f = os.path.join(REPO_ROOT, "adaptive_attacker_uaf/results", base,
                              f"repository_{slug}", f"summary_{TAG}.csv")
            if not os.path.exists(f):
                continue
            with open(f) as fh:
                rows = list(csv.DictReader(fh))
            if any(r.get("final_verdict") == "safe" for r in rows):
                flipped.add(slug)
        n = len(gt)
        k = len(flipped)
        print(f"{name:<10} {n:>9} {k:>8} {100*k/n:>7.1f}%" if n else f"{name:<10} {'n/a':>9}")


if __name__ == "__main__":
    main()
