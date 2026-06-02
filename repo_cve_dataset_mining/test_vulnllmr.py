#!/usr/bin/env python3
"""
Test VulnLLM-R on the filter-3 candidates.
Sends each candidate's buggy full_file to the served detector at localhost:8008.
"""
import json
import sys
from pathlib import Path

import requests

URL = "http://localhost:8008"
IN  = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "f3_dedup.jsonl"


def make_buggy(rec):
    fc = rec.get("_fixed_code", "")
    vc = rec.get("vulnerable_code", "")
    ff = rec.get("full_file", "")
    if fc and fc.strip() in ff:
        return ff.replace(fc.strip(), vc.strip(), 1)
    return ff


def detect(code: str, func_name: str, file_path: str) -> dict:
    body = {
        "code": code,
        "context": "",
        "target_function": code,
        "function_name": func_name,
        "file_name": Path(file_path).name,
    }
    r = requests.post(f"{URL}/detect", json=body, timeout=300)
    r.raise_for_status()
    return r.json()


def main():
    rows = [json.loads(l) for l in IN.read_text().splitlines()]
    print(f"Testing {len(rows)} candidates against VulnLLM-R at {URL}\n")

    results = []
    for i, rec in enumerate(rows):
        buggy = make_buggy(rec)
        tag = f"[{i+1}/{len(rows)}]"
        fn  = rec["func_name"]
        fp  = rec["file_path"]
        print(f"{tag} {rec['cve_id']:20} {fn:35} ...", end=" ", flush=True)
        try:
            out = detect(buggy, fn, fp)
            verdict   = out.get("verdict", "?")
            reasoning = out.get("reasoning", "")[:200].replace("\n", " ")
            symbol    = "✓ VULN" if verdict == "vulnerable" else "✗ safe"
            print(f"{symbol}")
            if verdict == "vulnerable":
                print(f"          {reasoning}")
        except Exception as e:
            print(f"ERROR: {e}")
            out = {"verdict": "error"}
        results.append({
            "cve_id":    rec["cve_id"],
            "func_name": fn,
            "file_path": fp,
            **out,
        })

    print(f"\n{'='*60}")
    detected = [r for r in results if r.get("verdict") == "vulnerable"]
    missed   = [r for r in results if r.get("verdict") != "vulnerable"]
    print(f"VulnLLM-R detected: {len(detected)}/{len(results)}")
    print("\nHITs:")
    for r in detected:
        print(f"  ✓ {r['cve_id']:20} {r['func_name']}")
    print("\nMISSes:")
    for r in missed:
        print(f"  ✗ {r['cve_id']:20} {r['func_name']}  [{r.get('verdict','?')}]")


if __name__ == "__main__":
    main()
