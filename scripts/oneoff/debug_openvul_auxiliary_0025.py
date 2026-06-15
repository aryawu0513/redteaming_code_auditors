#!/usr/bin/env python3
"""
Debug OpenVul auxiliary ordering on NPD-CVE-0025.

Tests three context configurations:
  1. no_aux    — only context_before + context_after
  2. aux_first — auxiliary_file + context_before + context_after  (current default)
  3. aux_last  — context_before + context_after + auxiliary_file

Run with OpenVul served at $DETECTOR_URL (default http://localhost:8008),
OR set --in-process to load the model directly (slow, uses GPU).

Usage:
    # via server (serve first: python detector_server.py --detector openvul --port 8009)
    DETECTOR_URL=http://localhost:8009 python scripts/oneoff/debug_openvul_auxiliary_0025.py

    # in-process
    python scripts/oneoff/debug_openvul_auxiliary_0025.py --in-process
"""
import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))

RECORD_PATH = REPO_ROOT / "benchmark/cvebench_full/baseline/repository_NPD-CVE-0025/NPD-CVE-0025_CLEAN.json"


def load_record() -> dict:
    data = json.loads(RECORD_PATH.read_text())
    return data[0] if isinstance(data, list) else data


def make_variants(rec: dict) -> list[tuple[str, dict]]:
    aux    = rec.get("auxiliary_file", "").strip()
    before = rec.get("context_before", "").strip()
    after  = rec.get("context_after", "").strip()

    def with_ctx(parts):
        ctx = "\n\n".join(p for p in parts if p)
        return {**rec, "context": ctx}

    return [
        ("no_aux",    with_ctx([before, after])),
        ("aux_first", with_ctx([aux, before, after])),
        ("aux_last",  with_ctx([before, after, aux])),
    ]


def run_via_server(variants: list[tuple[str, dict]], base_url: str) -> None:
    from detector_http import HttpDetectorClient
    client = HttpDetectorClient(base_url)
    for name, rec in variants:
        print(f"\n{'='*60}")
        print(f"  variant: {name}")
        print(f"  context len: {len(rec.get('context',''))} chars")
        print('='*60)
        result = client.detect(rec)
        print(f"  verdict : {result['verdict']}")
        print(f"  reasoning (first 500 chars):")
        print(f"  {result['reasoning'][:500]}")


def run_in_process(variants: list[tuple[str, dict]]) -> None:
    from detector_openvul import OpenVulDetector
    det = OpenVulDetector()
    for name, rec in variants:
        print(f"\n{'='*60}")
        print(f"  variant: {name}")
        print(f"  context len: {len(rec.get('context',''))} chars")
        print('='*60)
        # detector_openvul._build_prompt re-assembles from context_before/after/auxiliary,
        # so we pass context directly to bypass that by setting auxiliary_file="" and
        # context_before = already-assembled context, context_after = ""
        probe = {**rec,
                 "context_before": rec["context"],
                 "context_after":  "",
                 "auxiliary_file": ""}
        result = det.detect(probe)
        print(f"  verdict : {result['verdict']}")
        print(f"  reasoning (first 500 chars):")
        print(f"  {result['reasoning'][:500]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-process", action="store_true",
                        help="Load OpenVul model directly instead of using HTTP server")
    args = parser.parse_args()

    rec = load_record()
    print(f"Record: {rec.get('function_name')} ({rec.get('file_name')})")
    print(f"  target_function: {len(rec.get('target_function',''))} chars")
    print(f"  context_before:  {len(rec.get('context_before',''))} chars")
    print(f"  context_after:   {len(rec.get('context_after',''))} chars")
    print(f"  auxiliary_file:  {len(rec.get('auxiliary_file',''))} chars")

    variants = make_variants(rec)

    if args.in_process:
        run_in_process(variants)
    else:
        base_url = os.environ.get("DETECTOR_URL", "http://localhost:8008")
        run_via_server(variants, base_url)


if __name__ == "__main__":
    main()
