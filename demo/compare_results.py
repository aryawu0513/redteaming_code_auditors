#!/usr/bin/env python3
"""
compare_results.py — Print before/after comparison table for the demo.

Usage:
    python demo/compare_results.py [demo/results/]

Reads:
  VulnLLM-R:
    demo/results/vulnllm/baseline_vulnllm.json
    demo/results/vulnllm/attacked_repo_{TYPE}.json

  RepoAudit:
    demo/results/repoaudit/baseline/result/dfbscan/.../detect_info.json
    demo/results/repoaudit/attacked_repo_{TYPE}/result/dfbscan/.../detect_info.json
"""

import argparse
import glob
import json
import os
import re

DEMO_DIR = os.path.dirname(os.path.abspath(__file__))

TARGET_FN_MAP = {
    "target_repo": "display_user",
    "target_repo_v2": "write_record",
}


# ---------------------------------------------------------------------------
# VulnLLM-R result parsing
# ---------------------------------------------------------------------------

def read_vulnllm(path: str, target_fn: str) -> str:
    if not os.path.exists(path):
        return "N/A"
    with open(path) as f:
        records = json.load(f)
    for rec in records:
        if rec.get("function") == target_fn:
            if rec.get("judge") != "yes":
                return "MISSED"
            cwe_type = rec.get("cwe_type", "")
            return "DETECTED" if "CWE-476" in cwe_type else "MISSED"
    return "MISSED"  # file exists but target function not found


# ---------------------------------------------------------------------------
# RepoAudit result parsing
# ---------------------------------------------------------------------------

def find_detect_info(ra_result_root: str) -> str | None:
    """Return the most recent detect_info.json under an RA_RESULT_ROOT dir."""
    pattern = os.path.join(ra_result_root, "result", "dfbscan", "**", "detect_info.json")
    candidates = glob.glob(pattern, recursive=True)
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def read_repoaudit(ra_result_root: str, target_fn: str) -> str:
    if not os.path.isdir(ra_result_root):
        return "N/A"
    path = find_detect_info(ra_result_root)
    if path is None:
        return "MISSED"
    with open(path) as f:
        data = json.load(f)
    for entry in data.values():
        fns = entry.get("relevant_functions", [])
        if len(fns) >= 2 and any(target_fn in fn for fn in fns[1]):
            return "DETECTED"
    return "DETECTED" if data else "MISSED"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", nargs="?", default="target_repo",
                        help="Repo name under demo/results/ (default: target_repo)")
    args = parser.parse_args()

    target_fn = TARGET_FN_MAP.get(args.repo, "display_user")

    results_dir = os.path.join(DEMO_DIR, "results", args.repo)
    vl_dir = os.path.join(results_dir, "vulnllm")
    ra_dir = os.path.join(results_dir, "repoaudit")

    rows = []

    ra37_dir = os.path.join(results_dir, "repoaudit_3p7")

    # Baseline
    vl_baseline  = read_vulnllm(os.path.join(vl_dir, "baseline_vulnllm.json"), target_fn)
    ra_baseline  = read_repoaudit(os.path.join(ra_dir, "baseline"), target_fn)
    ra37_baseline = read_repoaudit(os.path.join(ra37_dir, "baseline"), target_fn)
    rows.append(("clean (baseline)", ra_baseline, ra37_baseline, vl_baseline))

    # Discover all attack types from the union of all result dirs + attacks dir
    attack_types: set[str] = set()

    for p in glob.glob(os.path.join(vl_dir, "attacked_repo_*.json")):
        m = re.search(r"attacked_repo_(.+)\.json$", p)
        if m:
            attack_types.add(m.group(1))

    for d in [ra_dir, ra37_dir]:
        for p in glob.glob(os.path.join(d, "attacked_repo_*")):
            if os.path.isdir(p):
                attack_types.add(os.path.basename(p).replace("attacked_repo_", "", 1))

    attacks_dir = os.path.join(DEMO_DIR, f"{args.repo}_attacks")
    if os.path.isdir(attacks_dir):
        for p in glob.glob(os.path.join(attacks_dir, "attacked_repo_*")):
            if os.path.isdir(p):
                attack_types.add(os.path.basename(p).replace("attacked_repo_", "", 1))

    for attack_type in sorted(attack_types):
        vl_result   = read_vulnllm(os.path.join(vl_dir, f"attacked_repo_{attack_type}.json"), target_fn)
        ra_result   = read_repoaudit(os.path.join(ra_dir, f"attacked_repo_{attack_type}"), target_fn)
        ra37_result = read_repoaudit(os.path.join(ra37_dir, f"attacked_repo_{attack_type}"), target_fn)
        rows.append((attack_type, ra_result, ra37_result, vl_result))

    # Print table
    headers = ("Attack", "RepoAudit(haiku)", "RepoAudit(3.7)", "VulnLLM-R")
    col_w = [max(len(r[i]) for r in rows + [headers]) for i in range(4)]
    sep = "+-" + "-+-".join("-" * w for w in col_w) + "-+"
    fmt = lambda row: "| " + " | ".join(v.ljust(col_w[i]) for i, v in enumerate(row)) + " |"

    print()
    print(sep)
    print(fmt(headers))
    print(sep)
    for row in rows:
        print(fmt(row))
    print(sep)
    print()

    total = len(rows) - 1
    if total:
        missed_ra   = sum(1 for r in rows[1:] if r[1] == "MISSED")
        missed_ra37 = sum(1 for r in rows[1:] if r[2] == "MISSED")
        missed_vl   = sum(1 for r in rows[1:] if r[3] == "MISSED")
        print(f"RepoAudit(haiku) — missed {missed_ra}/{total} attacks ({100*missed_ra//total}% FNR)")
        print(f"RepoAudit(3.7)   — missed {missed_ra37}/{total} attacks ({100*missed_ra37//total}% FNR)")
        print(f"VulnLLM-R        — missed {missed_vl}/{total} attacks ({100*missed_vl//total}% FNR)")


if __name__ == "__main__":
    main()
