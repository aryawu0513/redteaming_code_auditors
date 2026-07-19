#!/usr/bin/env python3
"""
table_r0_pervariant.py — computes Table (\\label{tab:r0} in
writing_overleaf/main.tex): per-attack-type ASR, round-0 flip rate, and mean
rounds-to-flip at budget 5, pooled across all four detectors' D0 (undefended)
runs (adaptive_attacker/results/{base}/repository_*/summary_fromscratch_v1.csv
— the base runs, not stop-on-any-flip, so every type runs to completion or
budget exhaustion independently, matching the paper's "resume every remaining
attack type... until it either flips the detector or exhausts the refinement
budget" methodology).

Type name mapping (our codebase name -> paper name), from
adaptive_attacker/refine_loop_fromscratch.py's STYLE_SPECS:
  COT->COT, FT->FAKE_TEST, CG->CALL_GRAPH, AA_MSG->NOTE, AA_USR->USR,
  AA_CA->ASSERT, TOOL_ClangSA->TOOL_CLANGSA, TOOL_Coverity->TOOL_COVERITY,
  TOOL_Frama->TOOL_FRAMA, TOOL_Fuzzer->TOOL_FUZZER

Usage:
    python3 result_analysis/table_scripts/table_r0_pervariant.py
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
    stats = {t: {"n": 0, "flipped": 0, "round0": 0, "rounds_sum": 0} for t in TYPE_NAME}

    for base in SYSTEMS:
        gt = get_ground_truth_slugs(base)
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
                # NOTE: "static_verdict" is NOT the ground-truth gate — it's
                # this run's own round-0 outcome, so it reads "safe" for
                # exactly the round-0 flips (stop_reason=static_succeeded).
                # Ground truth is already established at the slug level via
                # baseline_gate (get_ground_truth_slugs); do not filter here.
                stats[atype]["n"] += 1
                if r.get("final_verdict") == "safe":
                    stats[atype]["flipped"] += 1
                    stats[atype]["rounds_sum"] += int(r.get("rounds_used", 0))
                    if r.get("rounds_used") == "0":
                        stats[atype]["round0"] += 1

    print(f"{'Type':<15} {'ASR':>7} {'Round-0':>9} {'Mean Rounds':>12}")
    rows_out = []
    for t, name in TYPE_NAME.items():
        s = stats[t]
        asr = 100 * s["flipped"] / s["n"] if s["n"] else float("nan")
        r0 = 100 * s["round0"] / s["n"] if s["n"] else float("nan")
        mean_rounds = s["rounds_sum"] / s["flipped"] if s["flipped"] else float("nan")
        rows_out.append((name, asr, r0, mean_rounds, s["n"]))
    rows_out.sort(key=lambda x: -x[1])
    for name, asr, r0, mean_rounds, n in rows_out:
        print(f"{name:<15} {asr:6.1f}% {r0:8.1f}% {mean_rounds:11.2f}   (n={n})")


if __name__ == "__main__":
    main()
