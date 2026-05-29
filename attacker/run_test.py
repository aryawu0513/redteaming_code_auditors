#!/usr/bin/env python3
"""
run_test.py — Compile and run a solution against an inline input or test case.

Behavior depends on whether a `build.yaml` manifest is present in CWD:

  WITH manifest, test.kind == 'exit_code':
    Compiles the solution + test driver and runs the resulting binary.
    --input-str / --input / --expected-* are ignored (the driver does its
    own assertions). Reports stdout + exit status.

  WITH manifest, test.kind == 'stdin_stdout':
    Compiles the solution alone, then runs it against the given input,
    optionally comparing to expected (same shape as the legacy mode below).

  WITHOUT manifest (leetcode-style):
    Bare gcc/g++ compile, run against given stdin, optional expected match.

Usage:
    run_test --code solution.cc                                 (exit_code mode)
    run_test --code solution.c --input-str "3\\n1 2 3"           (stdin_stdout)
    run_test --code solution.c --input-str "..." --expected-str "..."
    run_test --code solution.c --input FILE [--expected FILE]

Exit code:
    0  if no expected given, or if output matches expected (or driver exit 0)
    1  if output does not match, compile error, runtime error, or timeout
"""

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from build_manifest import BuildManifest  # noqa: E402
from pathlib import Path  # noqa: E402

MAX_OUTPUT = 2000  # chars


def _legacy_compile(src: str, binary: str, timeout: int = 30) -> tuple[bool, str]:
    compiler, std = ("gcc", "-std=c11") if src.endswith(".c") else ("g++", "-std=c++17")
    result = subprocess.run(
        [compiler, "-O0", std, "-o", binary, src],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def _manifest_compile(m: BuildManifest, solution: str, binary: str) -> tuple[bool, str]:
    cmd = m.compile_command(solution=solution, binary=binary)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _run_binary(binary: str, stdin_data: str, timeout: int):
    """Returns (stdout, stderr, timed_out, runtime_error)."""
    try:
        result = subprocess.run(
            [binary], input=stdin_data, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout, result.stderr, False, result.returncode != 0
    except subprocess.TimeoutExpired:
        return "", "", True, False


def _truncate(s: str, limit: int = MAX_OUTPUT) -> str:
    return s if len(s) <= limit else s[:limit] + f"\n... [truncated — {len(s)} chars total]"


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

    manifest = BuildManifest.from_dir(Path.cwd())

    # Resolve input/expected from CLI (used in legacy + stdin_stdout manifest mode)
    if args.input_str is not None:
        stdin_data = args.input_str.replace("\\n", "\n")
    elif args.input_file:
        stdin_data = Path(args.input_file).read_text()
    else:
        stdin_data = ""

    expected = None
    if args.expected_str is not None:
        expected = args.expected_str.replace("\\n", "\n").rstrip()
    elif args.expected_file:
        expected = Path(args.expected_file).read_text().rstrip()

    with tempfile.TemporaryDirectory() as tmpdir:
        binary = os.path.join(tmpdir, "solution")

        # Compile
        if manifest is not None:
            ok, compile_err = _manifest_compile(manifest, args.code, binary)
        else:
            ok, compile_err = _legacy_compile(args.code, binary, timeout=30)
        if not ok:
            print(f"COMPILE_ERROR:\n{compile_err[:MAX_OUTPUT]}")
            sys.exit(1)

        # exit_code mode: the test driver is linked in; just run it
        if manifest is not None and manifest.test_kind == "exit_code":
            try:
                r = subprocess.run([binary], capture_output=True, text=True,
                                   timeout=max(args.timeout, manifest.test_timeout))
            except subprocess.TimeoutExpired:
                print("TIMEOUT")
                sys.exit(1)
            out = (r.stdout or "").rstrip()
            err = (r.stderr or "").strip()
            if r.returncode != 0:
                msg = f"RUNTIME_ERROR (exit {r.returncode})"
                if out:
                    msg += f"\n{_truncate(out)}"
                if err:
                    msg += f"\n[stderr]\n{_truncate(err)}"
                print(msg)
                sys.exit(1)
            if out:
                print(_truncate(out))
            else:
                print("(no output)")
            sys.exit(0)

        # stdin_stdout mode: run with provided input
        stdout, stderr, timed_out, runtime_error = _run_binary(binary, stdin_data, args.timeout)

    if timed_out:
        print("TIMEOUT")
        sys.exit(1)
    if runtime_error:
        msg = "RUNTIME_ERROR (exit non-zero)"
        if stderr.strip():
            msg += f"\n{_truncate(stderr.strip())}"
        print(msg)
        sys.exit(1)

    actual = stdout.rstrip()
    if stderr.strip():
        print(f"[stderr]: {stderr.strip()}", file=sys.stderr)

    if expected is None:
        print(_truncate(actual))
        sys.exit(0)
    if actual == expected:
        print("PASS")
        sys.exit(0)
    print(f"FAIL\nExpected:\n{_truncate(expected)}\nGot:\n{_truncate(actual)}")
    sys.exit(1)


if __name__ == "__main__":
    main()
