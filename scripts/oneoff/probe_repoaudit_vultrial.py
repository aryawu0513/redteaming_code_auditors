#!/usr/bin/env python3
"""
Quick end-to-end probe for RepoAudit and VulTrial detectors.
Runs a single baseline record through each detector and prints verdict + reasoning snippet.

Usage:
    python scripts/oneoff/probe_repoaudit_vultrial.py [--detector repoaudit|vultrial]
    (default: both)
"""
import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))
sys.path.insert(0, str(REPO_ROOT))

SAMPLE = REPO_ROOT / "benchmark/cvebench_full/baseline/repository_NPD-CVE-0006/NPD-CVE-0006_CLEAN.json"


def load_record() -> dict:
    records = json.loads(SAMPLE.read_text())
    return records[0]


def probe_repoaudit(record: dict) -> None:
    print("\n" + "="*60)
    print("PROBE: RepoAudit")
    print("="*60)
    from detector_repoaudit import RepoAuditDetector
    det = RepoAuditDetector(model_name="gpt-5-mini")
    t0 = time.time()
    result = det.detect(record)
    elapsed = time.time() - t0
    print(f"Verdict:  {result['verdict']}  ({elapsed:.1f}s)")
    reasoning = result.get("reasoning", "")
    print(f"Reasoning ({len(reasoning)} chars):\n{reasoning[:500]}{'...' if len(reasoning)>500 else ''}")


def probe_vultrial(record: dict) -> None:
    print("\n" + "="*60)
    print("PROBE: VulTrial")
    print("="*60)
    from detector_vultrial import VulTrialDetector
    det = VulTrialDetector(model="gpt-5-mini", mode="npd")
    t0 = time.time()
    result = det.detect(record)
    elapsed = time.time() - t0
    print(f"Verdict:  {result['verdict']}  ({elapsed:.1f}s)")
    reasoning = result.get("reasoning", "")
    print(f"Reasoning ({len(reasoning)} chars):\n{reasoning[:500]}{'...' if len(reasoning)>500 else ''}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", choices=["repoaudit", "vultrial", "both"], default="both")
    args = parser.parse_args()

    record = load_record()
    print(f"Sample: {record['slug']} / {record['file_name']}")

    if args.detector in ("repoaudit", "both"):
        probe_repoaudit(record)

    if args.detector in ("vultrial", "both"):
        probe_vultrial(record)


if __name__ == "__main__":
    main()
