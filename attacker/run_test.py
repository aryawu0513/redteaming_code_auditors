#!/usr/bin/env python3
"""
run_test.py — Compile and run a C++ file against a given input.

Usage (called by the mini-swe-agent via bash):
    run_test --code solution.cpp --input-str "3\\n1 2 3"
    run_test --code solution.cpp --input-str "3\\n1 2 3" --expected-str "6"
    run_test --code solution.cpp --input FILE [--expected FILE]

Exit code:
    0  if no expected given, or if output matches expected
    1  if output does not match, compile error, runtime error, or timeout
"""

import argparse
import os
import subprocess
import sys
import tempfile


def compile_cpp(src: str, binary: str, timeout: int = 30) -> tuple[bool, str]:
    result = subprocess.run(
        ["g++", "-O0", "-std=c++17", "-o", binary, src],
        capture_output=True, text=True, timeout=timeout,
    )
    ok = result.returncode == 0
    err = (result.stdout + result.stderr).strip()
    return ok, err


def run_binary(binary: str, stdin_data: str, timeout: int) -> tuple[str, str, bool, bool]:
    """Returns (stdout, stderr, timed_out, runtime_error)."""
    try:
        result = subprocess.run(
            [binary],
            input=stdin_data, capture_output=True, text=True, timeout=timeout,
        )
        timed_out = False
        runtime_error = result.returncode != 0
        return result.stdout, result.stderr, timed_out, runtime_error
    except subprocess.TimeoutExpired:
        return "", "", True, False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--input-str", default=None)
    parser.add_argument("--input", default=None, dest="input_file")
    parser.add_argument("--expected-str", default=None)
    parser.add_argument("--expected", default=None, dest="expected_file")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    if not os.path.isfile(args.code):
        print(f"COMPILE_ERROR: file not found: {args.code}")
        sys.exit(1)

    # Resolve input
    if args.input_str is not None:
        stdin_data = args.input_str.replace("\\n", "\n")
    elif args.input_file:
        with open(args.input_file) as f:
            stdin_data = f.read()
    else:
        stdin_data = ""

    # Resolve expected
    expected = None
    if args.expected_str is not None:
        expected = args.expected_str.replace("\\n", "\n").rstrip()
    elif args.expected_file:
        with open(args.expected_file) as f:
            expected = f.read().rstrip()

    with tempfile.TemporaryDirectory() as tmpdir:
        binary = os.path.join(tmpdir, "solution")
        ok, compile_err = compile_cpp(args.code, binary, timeout=30)
        if not ok:
            print(f"COMPILE_ERROR:\n{compile_err}")
            sys.exit(1)

        stdout, stderr, timed_out, runtime_error = run_binary(binary, stdin_data, args.timeout)

    if timed_out:
        print("TIMEOUT")
        sys.exit(1)
    if runtime_error:
        msg = f"RUNTIME_ERROR (exit non-zero)"
        if stderr.strip():
            msg += f"\n{stderr.strip()}"
        print(msg)
        sys.exit(1)

    actual = stdout.rstrip()

    if stderr.strip():
        print(f"[stderr]: {stderr.strip()}", file=sys.stderr)

    if expected is None:
        print(actual)
        sys.exit(0)

    if actual == expected:
        print("PASS")
        sys.exit(0)
    else:
        print(f"FAIL\nExpected:\n{expected}\nGot:\n{actual}")
        sys.exit(1)


if __name__ == "__main__":
    main()
