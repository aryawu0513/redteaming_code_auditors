#!/usr/bin/env python3
"""
Rerun RepoAudit on the 36 FN slugs that have an explicit NULL/nullptr literal
in target_function, using the fixed detector (files="" so auxiliary.cc is
co-loaded in a single scan) and o3-mini.

Previous run (repoaudit_o3mini_full) used files="*.c" which silently excluded
auxiliary.cc and skipped C++ slugs. This probe tests whether the fix recovers
additional TPs.

Output: adaptive_attacker/results/repoaudit_o3mini_null36_fixedfiles/
        repository_<slug>/baseline_gate_fromscratch_v1.json

Usage:
    cd /mnt/ssd/aryawu/redteaming_code_auditors
    export OPENAI_API_KEY=...
    python3 scripts/oneoff/probe_repoaudit_null36_fixedfiles.py [--dry-run]
"""
import argparse
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
BENCH_DIR = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
OLD_RESULTS = REPO_ROOT / "adaptive_attacker" / "results" / "repoaudit_o3mini_full"
OUT_DIR = REPO_ROOT / "adaptive_attacker" / "results" / "repoaudit_o3mini_null36_fixedfiles"

NULL_RE = re.compile(r'\bNULL\b|\bnullptr\b')

# 36 FN slugs with NULL literal in target_function (pre-computed)
FN_NULL_SLUGS = [
    "NPD-CVE-0054", "NPD-CVE-0078", "NPD-CVE-0089", "NPD-CVE-0130",
    "NPD-CVE-0190", "NPD-CVE-0192", "NPD-CVE-0195", "NPD-CVE-0198",
    "NPD-CVE-0236", "NPD-CVE-0238", "NPD-CVE-0240", "NPD-CVE-0292",
    "NPD-CVE-0297", "NPD-CVE-0303", "NPD-CVE-0305", "NPD-CVE-0394",
    "NPD-CVE-0396", "NPD-CVE-0397", "NPD-CVE-0434", "NPD-CVE-0485",
    "NPD-CVE-0488", "NPD-CVE-0580", "NPD-CVE-0672", "NPD-CVE-0685",
    "NPD-CVE-0686", "NPD-CVE-0688", "NPD-CVE-0691", "NPD-CVE-0694",
    "NPD-CVE-0736", "NPD-CVE-0784", "NPD-CVE-0785", "NPD-CVE-0822",
    "NPD-CVE-0823", "NPD-CVE-0825", "NPD-CVE-0826", "NPD-CVE-0827",
]


def load_record(slug: str) -> dict | None:
    clean = BENCH_DIR / f"repository_{slug}" / f"{slug}_CLEAN.json"
    if not clean.exists():
        print(f"  [skip] {slug} — CLEAN.json missing")
        return None
    rec = json.loads(clean.read_text())
    if isinstance(rec, list):
        rec = rec[0]
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--dry-run", action="store_true",
                    help="Print what would be run without calling the detector")
    ap.add_argument("--resume", action="store_true", default=True,
                    help="Skip slugs that already have output (default: True)")
    ap.add_argument("--no-resume", dest="resume", action="store_false")
    args = ap.parse_args()

    if not args.dry_run:
        sys.path.insert(0, str(REPO_ROOT))
        from adaptive_attacker.detector_repoaudit import RepoAuditDetector
        detector = RepoAuditDetector(
            model_name="o3-mini",
            language="Cpp",
            bug_type="NPD",
            files="",   # fixed: load all files together (solution.c + auxiliary.cc)
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Output → {OUT_DIR}")
    print(f"Slugs  : {len(FN_NULL_SLUGS)}")
    print()

    new_tp = 0
    for i, slug in enumerate(FN_NULL_SLUGS, 1):
        out_path = OUT_DIR / f"repository_{slug}" / "baseline_gate_fromscratch_v1.json"
        if args.resume and out_path.exists():
            existing = json.loads(out_path.read_text())
            v = existing.get("verdict", "?")
            print(f"  [{i:02d}/{len(FN_NULL_SLUGS)}] {slug}  SKIP (already done, verdict={v})")
            if v == "vulnerable":
                new_tp += 1
            continue

        rec = load_record(slug)
        if rec is None:
            continue

        has_aux = bool(rec.get("auxiliary_file", "").strip())
        lang = rec.get("language", "c")
        print(f"  [{i:02d}/{len(FN_NULL_SLUGS)}] {slug}  lang={lang}  aux={'yes' if has_aux else 'no'}", end="", flush=True)

        if args.dry_run:
            print("  [DRY RUN]")
            continue

        try:
            result = detector.detect(rec)
        except Exception as exc:
            result = {"verdict": "error", "reasoning": str(exc), "votes": {}}

        verdict = result.get("verdict", "error")
        print(f"  → {verdict}")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({
            "slug": slug,
            "verdict": verdict,
            "votes": result.get("votes", {}),
            "reasoning": result.get("reasoning", ""),
        }, indent=2))

        if verdict == "vulnerable":
            new_tp += 1

    print()
    print(f"Done. New TPs in this probe: {new_tp}/{len(FN_NULL_SLUGS)}")
    print(f"Previous baseline on these slugs: 0/{len(FN_NULL_SLUGS)} (all were FN)")


if __name__ == "__main__":
    main()
