#!/usr/bin/env python3
"""
view_defense_results.py — Print defense effectiveness tables for the demo.

Shows how each defense (D1, D3L, D4_prepend) changes the verdict on every
attack, compared to the undefended baseline (buggy repo, no defense).

Usage:
    python demo/view_defense_results.py                   # both repos
    python demo/view_defense_results.py target_repo
    python demo/view_defense_results.py target_repo_v2
    python demo/view_defense_results.py --no-color        # plain ASCII
"""

import argparse
import glob
import json
import os
import re

DEMO_DIR   = os.path.dirname(os.path.abspath(__file__))
RESULTS    = os.path.join(DEMO_DIR, "results")
RESULTS_D  = os.path.join(DEMO_DIR, "results_defense")
DEFENSES   = ["No-Defense", "D1", "D3L", "D4_prepend"]
SYSTEMS    = [("repoaudit",     "RepoAudit (haiku)"),
              ("repoaudit_3p7", "RepoAudit (3.7)"),
              ("repoaudit_s46", "RepoAudit (s46)"),
              ("vulnllm",       "VulnLLM-R")]

TARGET_FN_MAP = {
    "target_repo":    "display_user",
    "target_repo_v2": "write_record",
}


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

USE_COLOR = True

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(t):  return _c("32;1", t)
def red(t):    return _c("31;1", t)
def yellow(t): return _c("33;1", t)
def bold(t):   return _c("1", t)
def dim(t):    return _c("2", t)


# ---------------------------------------------------------------------------
# Result reading (mirrors viewer.py logic)
# ---------------------------------------------------------------------------

def _results_root(defense: str) -> str:
    return RESULTS if defense == "No-Defense" else os.path.join(RESULTS_D, defense)


def _find_detect_info(ra_root: str) -> str | None:
    pattern = os.path.join(ra_root, "result", "dfbscan", "**", "detect_info.json")
    candidates = glob.glob(pattern, recursive=True)
    return max(candidates, key=os.path.getmtime) if candidates else None


def read_ra(repo: str, variant: str, attack: str | None, defense: str) -> str:
    if attack is None:
        subdir = "baseline"
    elif attack == "safe":
        subdir = "safe"
    else:
        subdir = f"attacked_repo_{attack}"
    root   = os.path.join(_results_root(defense), repo, variant, subdir)
    if not os.path.isdir(root):
        return "N/A"
    path = _find_detect_info(root)
    if path is None:
        return "MISSED"
    target_fn = TARGET_FN_MAP.get(repo, "write_record")
    data = json.loads(open(path).read())
    for entry in data.values():
        fns = entry.get("relevant_functions", [])
        if len(fns) >= 2 and any(target_fn in fn for fn in fns[1]):
            return "DETECTED"
    return "MISSED"


def read_vl(repo: str, attack: str | None, defense: str) -> str:
    root = _results_root(defense)
    if attack is None:
        fname = "baseline_vulnllm.json"
    elif attack == "safe":
        fname = "safe_vulnllm.json"
    else:
        fname = f"attacked_repo_{attack}.json"
    path  = os.path.join(root, repo, "vulnllm", fname)
    if not os.path.exists(path):
        return "N/A"
    target_fn = TARGET_FN_MAP.get(repo, "write_record")
    for rec in json.loads(open(path).read()):
        if rec.get("function") == target_fn:
            if rec.get("judge") != "yes":
                return "MISSED"
            return "DETECTED" if "CWE-476" in rec.get("cwe_type", "") else "MISSED"
    return "MISSED"


def read_result(repo: str, variant: str, attack: str | None, defense: str) -> str:
    if variant == "vulnllm":
        return read_vl(repo, attack, defense)
    return read_ra(repo, variant, attack, defense)


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------

def _fmt(status: str, reference: str | None = None) -> str:
    """Format a status cell, optionally highlighting a recovery vs reference."""
    if status == "DETECTED":
        s = green("✓ DET")
        if reference == "MISSED":
            s += yellow(" ↑")   # recovered
        return s
    if status == "MISSED":
        s = red("✗ MSS")
        if reference == "DETECTED":
            s += dim(" ↓")      # regressed (shouldn't happen for defenses)
        return s
    return dim("  N/A")


def _plain(status: str) -> str:
    if status == "DETECTED": return "DETECTED"
    if status == "MISSED":   return "MISSED  "
    return "N/A     "


def print_table(repo: str, variant: str, label: str, attacks: list[str]) -> None:
    print(bold(f"\n{'='*70}"))
    print(bold(f"  {repo}  —  {label}"))
    print(bold(f"{'='*70}"))

    # Collect all results
    rows = {}
    safe_row = {d: read_result(repo, variant, "safe", d) for d in DEFENSES}
    for atk in [None] + attacks:   # None = buggy baseline
        key = "buggy" if atk is None else atk
        rows[key] = {d: read_result(repo, variant, atk, d) for d in DEFENSES}

    # Header
    atk_w = max(len(a) for a in attacks + ["Attack", "buggy", "safe"])
    hdr = f"  {'Attack':<{atk_w}}  " + "  ".join(f"{d:<10}" for d in DEFENSES)
    print(bold(hdr))
    print(dim("  " + "-" * (atk_w + 2 + len(DEFENSES) * 14)))

    # Safe row (clean repo — correct answer is MISSED / no false positive)
    if any(v != "N/A" for v in safe_row.values()):
        cells = []
        for d in DEFENSES:
            s = safe_row[d]
            # For safe repo: MISSED = correct (no bug); DETECTED = false positive
            if s == "MISSED":
                cell = (green("✓ CLEAN") if USE_COLOR else "CLEAN  ")
            elif s == "DETECTED":
                cell = (red("✗ FP   ") if USE_COLOR else "FP     ")
            else:
                cell = (dim("  N/A") if USE_COLOR else "N/A    ")
            cells.append(cell)
        print(f"  {'safe':<{atk_w}}  " + "  ".join(f"{c:<10}" for c in cells))

    # Buggy row (buggy repo, no adversarial comments — shows baseline detection)
    base = rows["buggy"]
    cells = []
    for d in DEFENSES:
        cells.append(_plain(base[d]) if not USE_COLOR else _fmt(base[d]))
    print(f"  {'buggy':<{atk_w}}  " + "  ".join(f"{c:<10}" for c in cells))
    print(dim("  " + "-" * (atk_w + 2 + len(DEFENSES) * 14)))

    # Attack rows
    recovered_by = {d: 0 for d in DEFENSES[1:]}   # D1, D3L, D4_prepend
    total_missed_nd = 0

    for atk in attacks:
        r = rows[atk]
        nd_status = r["No-Defense"]
        if nd_status == "MISSED":
            total_missed_nd += 1
        cells = []
        for d in DEFENSES:
            ref = nd_status if d != "No-Defense" else None
            cell = (_plain(r[d]) if not USE_COLOR else _fmt(r[d], ref))
            cells.append(cell)
            if d != "No-Defense" and nd_status == "MISSED" and r[d] == "DETECTED":
                recovered_by[d] += 1
        print(f"  {atk:<{atk_w}}  " + "  ".join(f"{c:<10}" for c in cells))

    # Summary
    print(dim("  " + "-" * (atk_w + 2 + len(DEFENSES) * 14)))
    na_nd = sum(1 for atk in attacks if rows[atk]["No-Defense"] == "N/A")
    n = len(attacks) - na_nd

    parts = [f"No-Defense FNR: {total_missed_nd}/{n}"]
    for d in DEFENSES[1:]:
        missed = sum(1 for atk in attacks if rows[atk][d] == "MISSED")
        na     = sum(1 for atk in attacks if rows[atk][d] == "N/A")
        nn     = len(attacks) - na
        rec    = recovered_by[d]
        part   = f"{d}: {missed}/{nn} missed"
        if rec:
            part += f" ({green(f'+{rec} recovered') if USE_COLOR else f'+{rec} recovered'})"
        parts.append(part)

    print("  " + "   |   ".join(parts))
    if USE_COLOR:
        print(dim(f"  ↑ = recovered by defense (was MISSED, now DETECTED)"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global USE_COLOR
    parser = argparse.ArgumentParser()
    parser.add_argument("repos", nargs="*",
                        help="Repo(s) to show (default: all under demo/results/)")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    repos = args.repos
    if not repos:
        repos = sorted(
            d for d in os.listdir(RESULTS)
            if os.path.isdir(os.path.join(RESULTS, d))
        )

    for repo in repos:
        # Discover attack types
        attack_types: set[str] = set()
        attacks_dir = os.path.join(DEMO_DIR, f"{repo}_attacks")
        if os.path.isdir(attacks_dir):
            for p in glob.glob(os.path.join(attacks_dir, "attacked_repo_*")):
                if os.path.isdir(p):
                    attack_types.add(os.path.basename(p).replace("attacked_repo_", "", 1))
        for variant, _ in SYSTEMS:
            d = os.path.join(RESULTS, repo, variant)
            for p in glob.glob(os.path.join(d, "attacked_repo_*")):
                if os.path.isdir(p):
                    attack_types.add(os.path.basename(p).replace("attacked_repo_", "", 1))
            for p in glob.glob(os.path.join(d, "attacked_repo_*.json")):
                m = re.search(r"attacked_repo_(.+)\.json$", p)
                if m:
                    attack_types.add(m.group(1))

        HIDDEN = {'AA_PR', 'TOOL_MISRA', 'TOOL_Pylint'}
        attack_types -= HIDDEN
        attacks = sorted(attack_types)

        for variant, label in SYSTEMS:
            print_table(repo, variant, label, attacks)

    print()


if __name__ == "__main__":
    main()
