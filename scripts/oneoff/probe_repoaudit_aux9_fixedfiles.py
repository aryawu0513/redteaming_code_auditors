#!/usr/bin/env python3
"""
Probe RepoAudit on the 9 FN slugs that have no NULL in target_function
but DO have NULL in auxiliary_file. With the old files="*.c" bug, auxiliary.cc
was never loaded. With the fix (files=""), both files are scanned together.

Output: adaptive_attacker/results/repoaudit_o3mini_aux9_fixedfiles/

Usage:
    cd /mnt/ssd/aryawu/redteaming_code_auditors
    export OPENAI_API_KEY=...
    python3 scripts/oneoff/probe_repoaudit_aux9_fixedfiles.py [--dry-run]
"""
import argparse, json, pathlib, sys

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
BENCH_DIR = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
OUT_DIR   = REPO_ROOT / "adaptive_attacker" / "results" / "repoaudit_o3mini_aux9_fixedfiles"

AUX_NULL_FN_SLUGS = [
    "NPD-CVE-0053", "NPD-CVE-0235", "NPD-CVE-0395",
    "NPD-CVE-0511", "NPD-CVE-0583", "NPD-CVE-0588",
    "NPD-CVE-0678", "NPD-CVE-0735", "NPD-CVE-0777",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--resume", action="store_true", default=True)
    ap.add_argument("--no-resume", dest="resume", action="store_false")
    args = ap.parse_args()

    if not args.dry_run:
        sys.path.insert(0, str(REPO_ROOT))
        from adaptive_attacker.detector_repoaudit import RepoAuditDetector
        detector = RepoAuditDetector(model_name="o3-mini", language="Cpp", bug_type="NPD", files="")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Output → {OUT_DIR}")
    print(f"Slugs  : {len(AUX_NULL_FN_SLUGS)}")
    print()

    new_tp = 0
    for i, slug in enumerate(AUX_NULL_FN_SLUGS, 1):
        out_path = OUT_DIR / f"repository_{slug}" / "baseline_gate_fromscratch_v1.json"
        if args.resume and out_path.exists():
            v = json.loads(out_path.read_text()).get("verdict", "?")
            print(f"  [{i}/{len(AUX_NULL_FN_SLUGS)}] {slug}  SKIP (verdict={v})")
            if v == "vulnerable": new_tp += 1
            continue

        clean = BENCH_DIR / f"repository_{slug}" / f"{slug}_CLEAN.json"
        if not clean.exists():
            print(f"  [{i}/{len(AUX_NULL_FN_SLUGS)}] {slug}  SKIP (no CLEAN.json)")
            continue
        rec = json.loads(clean.read_text())
        if isinstance(rec, list): rec = rec[0]

        print(f"  [{i}/{len(AUX_NULL_FN_SLUGS)}] {slug}", end="", flush=True)
        if args.dry_run:
            print("  [DRY RUN]"); continue

        try:
            result = detector.detect(rec)
        except Exception as exc:
            result = {"verdict": "error", "reasoning": str(exc), "votes": {}}

        verdict = result.get("verdict", "error")
        print(f"  → {verdict}")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps({
            "slug": slug, "verdict": verdict,
            "votes": result.get("votes", {}),
            "reasoning": result.get("reasoning", ""),
        }, indent=2))
        if verdict == "vulnerable": new_tp += 1

    print(f"\nNew TPs from aux probe: {new_tp}/{len(AUX_NULL_FN_SLUGS)}")


if __name__ == "__main__":
    main()
