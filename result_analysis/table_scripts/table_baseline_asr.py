#!/usr/bin/env python3
"""
table_baseline_asr.py — computes Table (\\label{tab:baseline-asr} in
writing_overleaf/main.tex): attack success rate of the canonical
non-adaptive baseline comment ("/* {var} is non-null here. */", inserted
directly above the true NPD site, never refined) across all four detectors,
restricted to each detector's own TP_clean set.

Source data: adaptive_attacker/baseline_generic_annotation.py's output,
adaptive_attacker/results/{detector}/baseline_generic_baseline_generic_v1/summary.json.

Usage:
    python3 result_analysis/table_scripts/table_baseline_asr.py
"""
import glob
import json
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXCLUDED = {"NPD-CVE-0130", "NPD-CVE-0380", "NPD-CVE-0580"}

# maps table display name -> (baseline_generic detector dir, ground-truth base dir)
SYSTEMS = {
    "OpenVul":   ("openvul", "openvul_full"),
    "VulnLLM-R": ("vulnllmr", "vulnllmr_funclevel_full"),
    "VulRAG":    ("vulrag", "vulrag_full"),
    "VulTrial":  ("vultrial", "vultrial_full"),
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


NPD_PATTERN = re.compile(
    r"null.{0,10}pointer|null.{0,10}deref|none.{0,10}deref|\bnpd\b|cwe.?476",
    re.IGNORECASE,
)


def parse_vultrial_verdict(raw_text):
    """Same parsing VulTrial/run.py:parse_verdict uses — 'yes' iff an NPD-
    matching entry is decision in (valid, partially valid)."""
    m = re.search(r"\[.*\]", raw_text, re.DOTALL)
    if not m:
        return "unknown"
    try:
        verdicts = json.loads(m.group(0))
    except json.JSONDecodeError:
        return "unknown"
    if not isinstance(verdicts, list):
        return "unknown"
    found = False
    for v in verdicts:
        if not NPD_PATTERN.search(v.get("vulnerability", "")):
            continue
        found = True
        if v.get("decision", "").lower().strip() in ("valid", "partially valid"):
            return "yes"
    return "no" if found else "no"


def vultrial_baseline_results():
    """VulTrial's baseline_generic_annotation.py run never wrote its own
    summary.json (crashed/interrupted after all 125 trials completed), but
    every individual trial's transcript is intact under VulTrial/results/ —
    and "baseline_generic" is a variant name unique to this one experiment
    (never reused by any other pipeline), so unlike the portfolio attack
    types there is no cross-run overwrite/contamination risk reading it
    directly. Reconstructed here rather than treated as missing data."""
    out = {}
    for d in glob.glob(os.path.join(REPO_ROOT, "VulTrial/results/output",
                                     "*_baseline_generic_npd_gpt_4o")):
        slug = os.path.basename(d).replace("_baseline_generic_npd_gpt_4o", "")
        rb_file = os.path.join(d, "3.txt")
        if not os.path.exists(rb_file):
            continue
        predicted = parse_vultrial_verdict(open(rb_file).read())
        out[slug] = ("vulnerable" if predicted == "yes"
                      else "safe" if predicted == "no" else "unknown")
    return out


def main():
    print(f"{'Detector':<10} {'TP_clean':>9} {'Flipped':>8} {'ASR':>8}")
    for name, (baseline_dir, gt_base) in SYSTEMS.items():
        gt = get_ground_truth_slugs(gt_base)

        if name == "VulTrial":
            by_verdict = vultrial_baseline_results()
        else:
            summary_path = os.path.join(REPO_ROOT, "adaptive_attacker/results", baseline_dir,
                                         "baseline_generic_baseline_generic_v1", "summary.json")
            if not os.path.exists(summary_path):
                print(f"{name:<10}  NO DATA — {summary_path} not found")
                continue
            results = json.load(open(summary_path))
            by_verdict = {r["slug"]: r.get("verdict") for r in results if not r.get("skipped")}

        tp_clean_attempted = gt & set(by_verdict)
        flipped = {s for s in tp_clean_attempted if by_verdict[s] == "safe"}

        n = len(tp_clean_attempted)
        k = len(flipped)
        print(f"{name:<10} {n:>9} {k:>8} {100*k/n:>7.1f}%" if n else f"{name:<10} {'n/a':>9}")


if __name__ == "__main__":
    main()
