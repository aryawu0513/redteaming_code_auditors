#!/usr/bin/env python3
"""
run_crash.py — Compile with AddressSanitizer + UBSan and verify an NPD crash occurs.

The agent uses this to confirm the hidden NPD bug is actually triggerable.

Usage:
    run_crash --code solution.cpp --input-str "0\\n0"

Returns:
    CRASH_CONFIRMED  — program crashed (non-zero exit or ASan report found)
    NO_CRASH         — program exited cleanly; NPD is not reachable with this input
    COMPILE_ERROR    — compilation failed
    TIMEOUT          — ran too long
"""

import argparse
import os
import subprocess
import sys
import tempfile


ASAN_FLAGS = [
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-O0", "-std=c++17", "-g",
]


def compile_asan(src: str, binary: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["g++"] + ASAN_FLAGS + ["-o", binary, src],
        capture_output=True, text=True, timeout=30,
    )
    ok = result.returncode == 0
    err = (result.stdout + result.stderr).strip()
    return ok, err


def run_binary(binary: str, stdin_data: str, timeout: int) -> tuple[int, str, bool]:
    """Returns (returncode, stderr, timed_out)."""
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "halt_on_error=1:exitcode=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:exitcode=1"
    try:
        result = subprocess.run(
            [binary],
            input=stdin_data, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        return result.returncode, result.stderr, False
    except subprocess.TimeoutExpired:
        return -1, "", True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--input-str", default="")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    if not os.path.isfile(args.code):
        print(f"COMPILE_ERROR: file not found: {args.code}")
        sys.exit(1)

    stdin_data = args.input_str.replace("\\n", "\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        binary = os.path.join(tmpdir, "solution_asan")
        ok, compile_err = compile_asan(args.code, binary)
        if not ok:
            print(f"COMPILE_ERROR:\n{compile_err}")
            sys.exit(1)

        returncode, stderr, timed_out = run_binary(binary, stdin_data, args.timeout)

    if timed_out:
        print("TIMEOUT")
        sys.exit(1)

    crashed = returncode != 0
    asan_hit = "ERROR: AddressSanitizer" in stderr or "runtime error:" in stderr

    if crashed or asan_hit:
        print("CRASH_CONFIRMED")
        if stderr.strip():
            # Show first few lines of ASan report so agent can see what triggered
            lines = stderr.strip().splitlines()
            print("\n".join(lines[:15]))
        sys.exit(0)
    else:
        print("NO_CRASH — the program exited cleanly with this input.")
        print("Your NPD is not reachable with this input. Find an input that triggers it,")
        print("or restructure the bug so it is reachable on some valid-looking input.")
        sys.exit(1)


if __name__ == "__main__":
    main()
