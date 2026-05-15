#!/usr/bin/env python3
"""
submit.py — Run solution.cpp against all public + private tests for the current problem.

Resolves the problem by reading the parent directory name (repository_{SLUG}),
looking up the slug in experiments/problem_map.json, then finding the entry in
the JSONL dataset.

Usage (called from within an experiment directory):
    submit --code solution.cpp [--timeout 10]

Returns:
    PASS                        — all tests passed
    FAIL — M/N tests passed.    — some tests failed
    COMPILE_ERROR / TIMEOUT / RUNTIME_ERROR on systemic failures

Environment:
    DATA_PATH — override default JSONL path
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile


def compile_cpp(src: str, binary: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["g++", "-O0", "-std=c++17", "-o", binary, src],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def run_binary(binary: str, stdin_data: str, timeout: int) -> tuple[str, bool, bool]:
    try:
        r = subprocess.run([binary], input=stdin_data, capture_output=True, text=True, timeout=timeout)
        return r.stdout.rstrip(), r.returncode != 0, False
    except subprocess.TimeoutExpired:
        return "", False, True


def find_problem(slug: str, map_path: str, data_path: str) -> dict | None:
    with open(map_path) as f:
        problem_map = json.load(f)
    name = problem_map.get(slug)
    if name is None:
        return None
    with open(data_path) as f:
        for line in f:
            entry = json.loads(line)
            if entry["name"] == name:
                return entry
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    # Resolve paths relative to CWD (agent runs from inside experiment dir)
    cwd = os.getcwd()
    slug = os.path.basename(cwd).replace("repository_", "")

    attacker_dir = os.path.dirname(os.path.abspath(__file__))
    map_path = os.path.join(attacker_dir, "experiments", "problem_map.json")
    data_path = os.environ.get(
        "DATA_PATH",
        os.path.join(attacker_dir, "data", "cpp_pointer_problems.jsonl"),
    )

    if not os.path.isfile(args.code):
        print(f"COMPILE_ERROR: file not found: {args.code}")
        sys.exit(1)

    problem = find_problem(slug, map_path, data_path)
    if problem is None:
        print(f"ERROR: could not find problem for slug '{slug}'")
        sys.exit(1)

    # Collect all tests (public + private)
    tests = []
    for split in ("public_tests", "private_tests"):
        t = problem.get(split, {})
        inputs = t.get("input", [])
        outputs = t.get("output", [])
        tests.extend(zip(inputs, outputs))

    if not tests:
        print("ERROR: no tests found for this problem")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        binary = os.path.join(tmpdir, "solution")
        ok, err = compile_cpp(args.code, binary)
        if not ok:
            print(f"COMPILE_ERROR:\n{err}")
            sys.exit(1)

        passed = 0
        first_fail = None
        for i, (inp, expected) in enumerate(tests):
            actual, runtime_err, timed_out = run_binary(binary, inp, args.timeout)
            if timed_out:
                if first_fail is None:
                    first_fail = f"test {i} — TIMEOUT"
                continue
            if runtime_err:
                if first_fail is None:
                    first_fail = f"test {i} — RUNTIME_ERROR"
                continue
            if actual == expected.rstrip():
                passed += 1
            else:
                if first_fail is None:
                    first_fail = f"test {i} — wrong answer"

    n = len(tests)
    if passed == n:
        print("PASS")
        sys.exit(0)
    else:
        msg = f"FAIL — {passed}/{n} tests passed."
        if first_fail:
            msg += f" First failure: {first_fail}."
        print(msg)
        sys.exit(1)


if __name__ == "__main__":
    main()
