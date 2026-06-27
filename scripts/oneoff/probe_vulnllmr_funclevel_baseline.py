#!/usr/bin/env python3
"""
probe_vulnllmr_funclevel_baseline.py

Quick baseline-TPR probe for VulnLLM-R in function-level (non-agentic) mode.
Loads the model once, runs detect() on the CLEAN (un-attacked) record of a
handful of cvebench_full slugs, and prints the verdict. All cvebench samples
are known-vulnerable, so baseline TPR = fraction detected "vulnerable".

Run on a free GPU (nvidia-smi first):
    CUDA_VISIBLE_DEVICES=0 python scripts/oneoff/probe_vulnllmr_funclevel_baseline.py
Optionally pass slugs:
    CUDA_VISIBLE_DEVICES=0 python scripts/oneoff/probe_vulnllmr_funclevel_baseline.py \
        NPD-CVE-0006 NPD-CVE-0027
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))

BASELINE_DIR = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
DEFAULT_SLUGS = ["NPD-CVE-0006", "NPD-CVE-0025", "NPD-CVE-0026",
                 "NPD-CVE-0027", "NPD-CVE-0047"]


def load_clean(slug: str) -> dict:
    p = BASELINE_DIR / f"repository_{slug}" / f"{slug}_CLEAN.json"
    d = json.loads(p.read_text())
    return d[0] if isinstance(d, list) else d


def main() -> None:
    slugs = sys.argv[1:] or DEFAULT_SLUGS
    from detector_vulnllmr import VulnLLMRDetector
    det = VulnLLMRDetector(tp=1, mode="funclevel")

    results = []
    for slug in slugs:
        rec = load_clean(slug)
        out = det.detect(rec)
        verdict = out["verdict"]
        results.append((slug, verdict))
        print(f"  {slug}: {verdict}", flush=True)

    tp = sum(1 for _, v in results if v == "vulnerable")
    n = len(results)
    print(f"\nBaseline TPR (funclevel): {tp}/{n} = {100*tp/n:.0f}%")
    for slug, v in results:
        flag = "TP" if v == "vulnerable" else ("FN" if v == "safe" else "ERR")
        print(f"  {flag:3} {slug}  ({v})")


if __name__ == "__main__":
    main()
