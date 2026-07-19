#!/usr/bin/env python3
"""
table2_attackeffectiveness.py — computes Table 2 (\\label{tab:headline} in
writing_overleaf/main.tex): per-detector attack effectiveness at budget 5,
D0 (undefended), union over all 10 attack types.

TP_clean = ground-truth-attackable slugs (baseline_gate_fromscratch_v1.json
verdict == "vulnerable" on the bare, unannotated code).
Flipped   = TP_clean slugs where ANY of the 10 attack types' final_verdict
            == "safe" within budget 5 (summary_fromscratch_v1.csv).
ASR       = Flipped / TP_clean.

Usage:
    python3 result_analysis/table_scripts/table2_attackeffectiveness.py
"""
import csv
import glob
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXCLUDED = {"NPD-CVE-0130", "NPD-CVE-0380", "NPD-CVE-0580"}

SYSTEMS = {
    "OpenVul":   "openvul_full",
    "VulnLLM-R": "vulnllmr_funclevel_full",
    "VulRAG":    "vulrag_full",
    "VulTrial":  "vultrial_full",
}


def get_ground_truth_slugs(base):
    slugs = set()
    for rd in glob.glob(os.path.join(REPO_ROOT, "adaptive_attacker/results", base, "repository_NPD-CVE-*")):
        slug = os.path.basename(rd).replace("repository_", "")
        if slug in EXCLUDED:
            continue
        f = os.path.join(rd, "baseline_gate_fromscratch_v1.json")
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
            f = os.path.join(REPO_ROOT, "adaptive_attacker/results", base,
                              f"repository_{slug}", "summary_fromscratch_v1.csv")
            if not os.path.exists(f):
                continue
            with open(f) as fh:
                rows = list(csv.DictReader(fh))
            if any(r.get("final_verdict") == "safe" for r in rows):
                flipped.add(slug)
        n = len(gt)
        k = len(flipped)
        print(f"{name:<10} {n:>9} {k:>8} {100*k/n:>7.1f}%")


if __name__ == "__main__":
    main()
