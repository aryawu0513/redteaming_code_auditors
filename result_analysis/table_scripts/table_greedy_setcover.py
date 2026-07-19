#!/usr/bin/env python3
"""
table_greedy_setcover.py — computes Table (\\label{tab:greedy} in
writing_overleaf/main.tex): greedy set-cover order over all 10 attack types,
joint across all four detectors' D0 runs. N = total (slug, detector) pairs
across all four detectors' ground-truth-attackable sets; "attainable" =
pairs flipped by at least one of the 10 types within budget 5.

At each step, picks the type covering the most still-uncovered pairs.

Usage:
    python3 result_analysis/table_scripts/table_greedy_setcover.py
"""
import csv
import glob
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXCLUDED = {"NPD-CVE-0130", "NPD-CVE-0380", "NPD-CVE-0580"}
SYSTEMS = ["openvul_full", "vulnllmr_funclevel_full", "vulrag_full", "vultrial_full"]
TYPE_NAME = {
    "COT": "COT", "FT": "FAKE_TEST", "CG": "CALL_GRAPH", "AA_MSG": "NOTE",
    "AA_USR": "USR", "AA_CA": "ASSERT", "TOOL_ClangSA": "TOOL_CLANGSA",
    "TOOL_Coverity": "TOOL_COVERITY", "TOOL_Frama": "TOOL_FRAMA",
    "TOOL_Fuzzer": "TOOL_FUZZER",
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
    # pair_id = (detector_base, slug); coverage[type] = set of pair_ids it flips
    all_pairs = set()
    coverage = {t: set() for t in TYPE_NAME}

    # N = ALL benchmark slugs x all 4 detectors (128 x 4 = 512), not just
    # each detector's own TP_clean subset — pairs outside TP_clean simply
    # contribute 0 to "attainable" (no baseline vulnerability to flip).
    all_slugs = set()
    for base in SYSTEMS:
        for rd in glob.glob(os.path.join(REPO_ROOT, "adaptive_attacker/results", base, "repository_NPD-CVE-*")):
            slug = os.path.basename(rd).replace("repository_", "")
            if slug not in EXCLUDED:
                all_slugs.add(slug)

    for base in SYSTEMS:
        gt = get_ground_truth_slugs(base)
        for slug in all_slugs:
            all_pairs.add((base, slug))
        for slug in gt:
            f = os.path.join(REPO_ROOT, "adaptive_attacker/results", base,
                              f"repository_{slug}", "summary_fromscratch_v1.csv")
            if not os.path.exists(f):
                continue
            with open(f) as fh:
                rows = list(csv.DictReader(fh))
            for r in rows:
                atype = r.get("annotation_type")
                if atype not in TYPE_NAME:
                    continue
                if r.get("final_verdict") == "safe":
                    coverage[atype].add((base, slug))

    attainable = set()
    for s in coverage.values():
        attainable |= s

    N = len(all_pairs)
    print(f"N = {N} slug-detector pairs, {len(attainable)} attainable "
          f"({100*len(attainable)/N:.1f}%)\n")

    covered = set()
    remaining_types = dict(coverage)
    pick = 0
    print(f"{'Pick':<5}{'Type':<16}{'Marginal':>9}{'% of max':>10}")
    max_cov = len(attainable)
    while remaining_types and len(covered) < max_cov:
        best_type = max(remaining_types, key=lambda t: len(remaining_types[t] - covered))
        marginal = len(remaining_types[best_type] - covered)
        if marginal == 0:
            break
        covered |= remaining_types[best_type]
        pick += 1
        print(f"{pick:<5}{TYPE_NAME[best_type]:<16}{marginal:>9}{100*len(covered)/max_cov:>9.1f}%")
        del remaining_types[best_type]


if __name__ == "__main__":
    main()
