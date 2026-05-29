#!/usr/bin/env python3
"""
detect_cli.py — Shell tool for mini-swe-agent to invoke the detector HTTP server.

Reads the (edited) target function from a .c file, merges it into the
corresponding record JSON, posts to detector_server, and prints a structured
response the agent can parse.

Usage:
    detect_cli.py --code solution_FT.c --record record_FT.json
    detect_cli.py --code solution_FT.c                 # auto-derives record path

Convention: solution_{TYPE}.c contains ONLY the target function (with any
annotation comment the agent has added). The non-changing context (includes,
helper definitions) lives in record_{TYPE}.json under the "context" field
and is kept in sync by the server-side merge.

Output format (printed to stdout, parseable by the agent):

    VERDICT: safe          ← or vulnerable
    VOTES: {"has_vul": 1, "no_vul": 7}
    --- REASONING ---
    <detector reasoning text>
    --- END ---
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True, type=Path,
                        help="Path to the .c file containing the (edited) target function.")
    parser.add_argument("--record", type=Path, default=None,
                        help="Path to the OpenVul-format record JSON. Defaults to "
                             "record_{TYPE}.json next to --code.")
    parser.add_argument("--server",
                        default=os.environ.get("DETECTOR_URL", "http://localhost:8008"),
                        help="Detector server base URL (env DETECTOR_URL, default http://localhost:8008).")
    parser.add_argument("--timeout", type=float, default=3600.0,
                        help="HTTP read timeout in seconds (default 3600 = 1 hour). "
                             "Detector calls on hard inputs can take 30-60 min with "
                             "n=8 + max_tokens=32768.")
    args = parser.parse_args()

    if not args.code.exists():
        print(f"ERROR: code file not found: {args.code}", file=sys.stderr)
        return 2

    record_path = args.record
    if record_path is None:
        # solution_{TYPE}.c  →  record_{TYPE}.json
        stem = args.code.stem
        if stem.startswith("solution_"):
            type_part = stem[len("solution_"):]
            record_path = args.code.parent / f"record_{type_part}.json"
        else:
            print(f"ERROR: cannot derive record path from {args.code} "
                  f"(expected solution_<TYPE>.c)", file=sys.stderr)
            return 2

    if not record_path.exists():
        print(f"ERROR: record file not found: {record_path}", file=sys.stderr)
        return 2

    record = json.loads(record_path.read_text())
    if isinstance(record, list):
        record = record[0]

    new_target = args.code.read_text()
    record["target_function"] = new_target
    record["code"] = (
        "// context\n" + record.get("context", "")
        + "\n// target function\n" + new_target
    )
    record.setdefault("file_name", args.code.name)

    body = {
        "code": record["code"],
        "context": record.get("context", ""),
        "target_function": record["target_function"],
        "function_name": record["function_name"],
        "file_name": record["file_name"],
    }

    try:
        resp = requests.post(f"{args.server}/detect", json=body, timeout=args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"ERROR: detector request failed: {exc}", file=sys.stderr)
        return 3

    if resp.status_code != 200:
        print(f"ERROR: detector returned {resp.status_code}: {resp.text}", file=sys.stderr)
        return 3

    data = resp.json()
    print(f"VERDICT: {data['verdict']}")
    print(f"VOTES: {json.dumps(data.get('votes', {}))}")
    print("--- REASONING ---")
    print(data.get("reasoning", ""))
    print("--- END ---")
    return 0


if __name__ == "__main__":
    sys.exit(main())
