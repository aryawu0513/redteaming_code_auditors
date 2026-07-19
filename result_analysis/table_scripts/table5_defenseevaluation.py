#!/usr/bin/env python3
"""
table5_defenseevaluation.py — computes Table 5 (\\label{tab:defenses} in
writing_overleaf/main.tex): D0/D1/D2/D3(=our D5)/D4(=our D3B) round-0 and
end-to-end ASR, combined across all 10 attack types.

D0: union over all 10 types directly from the undefended run
    (adaptive_attacker/results/{base}/repository_*/summary_fromscratch_v1.csv).
D1/D2/D3: portfolio (5-type) flip set from the seeded run, UNION'd with the
    stage-2 (informal 5-type, full budget) flip set restricted to slugs the
    portfolio never flipped — see scripts/oneoff/run_informal_extension.py
    and scripts/oneoff/compute_d1_unflipped_slugs.py for how those pieces
    are produced. This script only consumes their output; it does not
    itself launch any adaptive attacker calls.
D4 (our D3B, screening hard-cut): reported separately, taken from
    defenses/d3_proxy_check.py --full-scale's saved JSON output in
    defenses/screening_results/ (adversarial MISS rate, i.e. 100% - catch
    rate) — not recomputed here.

Usage:
    python3 result_analysis/table_scripts/table5_defenseevaluation.py
"""
import csv
import glob
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXCLUDED = {"NPD-CVE-0130", "NPD-CVE-0380", "NPD-CVE-0580"}
PORTFOLIO = {"COT", "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer"}
INFORMAL = ["AA_MSG", "AA_USR", "AA_CA", "FT", "CG"]

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


def d0_flips(base, gt, mode):
    """mode='round0' -> rounds_used==0 & safe. mode='end' -> any round & safe."""
    flipped = set()
    for slug in gt:
        f = os.path.join(REPO_ROOT, "adaptive_attacker/results", base,
                          f"repository_{slug}", "summary_fromscratch_v1.csv")
        if not os.path.exists(f):
            continue
        with open(f) as fh:
            rows = list(csv.DictReader(fh))
        for r in rows:
            if r.get("final_verdict") != "safe":
                continue
            if mode == "end" or (mode == "round0" and r.get("rounds_used") == "0"):
                flipped.add(slug)
    return flipped


def portfolio_flips(base, defense, gt, mode):
    portfolio_dir = f"{base}_{defense.lower()}adaptive_seeded"
    flipped = set()
    for f in glob.glob(os.path.join(REPO_ROOT, "adaptive_attacker/results", portfolio_dir,
                                     "repository_NPD-CVE-*", "summary_*.csv")):
        slug = os.path.basename(os.path.dirname(f)).replace("repository_", "")
        with open(f) as fh:
            rows = [r for r in csv.DictReader(fh) if r.get("annotation_type") in PORTFOLIO]
        for r in rows:
            if r.get("final_verdict") != "safe":
                continue
            if mode == "end" or (mode == "round0" and r.get("rounds_used") == "0"):
                flipped.add(slug)
    return flipped & gt


def informal_stage2_flips(base, defense, unflipped_slugs):
    system = f"{base}_{defense.lower()}adaptive_stage2_informal"
    run_tag = f"{defense.lower()}_stage2_informal_v1"
    flipped = set()
    for slug in unflipped_slugs:
        for atype in INFORMAL:
            rp = os.path.join(REPO_ROOT, "adaptive_attacker/results", system,
                               f"repository_{slug}", f"adaptive_{atype}_{run_tag}", "result.json")
            if not os.path.exists(rp):
                continue
            r = json.load(open(rp))
            if r.get("final_verdict") == "safe":
                flipped.add(slug)
    return flipped


def informal_round0_flips(base, defense):
    system = f"{base}_{defense.lower()}adaptive_round0_informal"
    run_tag = f"{defense.lower()}_round0_informal_v1"
    flipped = set()
    for rd in glob.glob(os.path.join(REPO_ROOT, "adaptive_attacker/results", system, "repository_NPD-CVE-*")):
        slug = os.path.basename(rd).replace("repository_", "")
        for atype in INFORMAL:
            rp = os.path.join(rd, f"adaptive_{atype}_{run_tag}", "round_0.json")
            if not os.path.exists(rp):
                continue
            r = json.load(open(rp))
            if r.get("detector_verdict") == "safe":
                flipped.add(slug)
    return flipped


def main():
    print(f"{'Detector':<10} {'Defense':<4} {'GT':>4}  {'Round-0 ASR':>12}  {'End-to-end ASR':>15}")
    for name, base in SYSTEMS.items():
        gt = get_ground_truth_slugs(base)
        n = len(gt)

        d0_r0 = d0_flips(base, gt, "round0")
        d0_end = d0_flips(base, gt, "end")
        print(f"{name:<10} {'D0':<4} {n:>4}  {100*len(d0_r0)/n:>11.1f}%  {100*len(d0_end)/n:>14.1f}%")

        for defense in ["D1", "D2", "D5"]:
            pf_r0 = portfolio_flips(base, defense, gt, "round0")
            pf_end = portfolio_flips(base, defense, gt, "end")
            unflipped = gt - pf_end
            inf_stage2 = informal_stage2_flips(base, defense, unflipped) & gt
            inf_r0 = informal_round0_flips(base, defense) & gt

            combined_r0 = pf_r0 | inf_r0
            combined_end = pf_end | inf_stage2

            label = "D3" if defense == "D5" else defense  # paper naming: our D5 = paper's D3
            print(f"{name:<10} {label:<4} {n:>4}  {100*len(combined_r0)/n:>11.1f}%  {100*len(combined_end)/n:>14.1f}%")
        print()


if __name__ == "__main__":
    main()
