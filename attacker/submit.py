#!/usr/bin/env python3
"""
submit.py — Run the submitted solution against all tests for the current site.

Behavior depends on whether a `build.yaml` manifest is present in CWD:

  WITH manifest (e.g. sofa-pbrpc NPD sites):
    - Compile {solution} + {test_driver} → binary using manifest.compile.command
    - For test.kind == 'exit_code': PASS if the binary exits 0
    - For test.kind == 'stdin_stdout': loop manifest.test.cases, compare stdouts

  WITHOUT manifest (existing leetcode-style problems):
    - Compile with bare gcc/g++ -O0 -std=...
    - Use local tests/input_N.txt + tests/output_N.txt, falling back to the
      JSONL dataset entry resolved via problem_map.json

Usage (called from within an experiment/site directory):
    submit --code solution.cpp [--timeout 10]

Returns:
    PASS                        — all tests passed
    FAIL — M/N tests passed.    — some tests failed
    COMPILE_ERROR / TIMEOUT / RUNTIME_ERROR on systemic failures
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

# Add the attacker directory to sys.path so we can import build_manifest
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from build_manifest import BuildManifest  # noqa: E402
from pathlib import Path  # noqa: E402


# ---------------------------------------------------------------------------
# Legacy (no-manifest) compile/run — preserved for existing leetcode sites
# ---------------------------------------------------------------------------

def _legacy_compile(src: str, binary: str) -> tuple[bool, str]:
    compiler, std = ("gcc", "-std=c11") if src.endswith(".c") else ("g++", "-std=c++17")
    result = subprocess.run(
        [compiler, "-O0", std, "-o", binary, src],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def _run_binary(binary: str, stdin_data: str, timeout: int) -> tuple[str, bool, bool]:
    try:
        r = subprocess.run([binary], input=stdin_data, capture_output=True, text=True, timeout=timeout)
        return r.stdout.rstrip(), r.returncode != 0, False
    except subprocess.TimeoutExpired:
        return "", False, True


def _find_problem(slug: str, map_path: str, data_path: str) -> dict | None:
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


# ---------------------------------------------------------------------------
# Manifest-driven compile (sofa-pbrpc and other custom-build sites)
# ---------------------------------------------------------------------------

def _manifest_compile(m: BuildManifest, solution: str, binary: str) -> tuple[bool, str]:
    cmd = m.compile_command(solution=solution, binary=binary)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _run_manifest_tests(m: BuildManifest, binary: str, timeout: int) -> tuple[int, int, str | None]:
    """Returns (passed, total, first_fail_msg)."""
    if m.test_kind == "exit_code":
        try:
            r = subprocess.run([binary], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 0, 1, "exit_code test — TIMEOUT"
        if r.returncode == 0:
            return 1, 1, None
        msg = f"exit_code test — RC={r.returncode}"
        tail = (r.stdout + "\n" + r.stderr).strip()
        if tail:
            msg += f"\n{tail[:600]}"
        return 0, 1, msg

    elif m.test_kind == "stdin_stdout":
        cases = m.test_cases
        passed = 0
        first_fail = None
        for i, (inp_path, out_path) in enumerate(cases):
            try:
                inp = Path(inp_path).read_text() if inp_path else ""
                expected = Path(out_path).read_text().rstrip() if out_path else ""
            except FileNotFoundError as e:
                return passed, len(cases), f"test {i} — missing file: {e}"
            actual, runtime_err, timed_out = _run_binary(binary, inp, timeout)
            if timed_out:
                first_fail = first_fail or f"test {i} — TIMEOUT"
            elif runtime_err:
                first_fail = first_fail or f"test {i} — RUNTIME_ERROR"
            elif actual == expected:
                passed += 1
            else:
                first_fail = first_fail or f"test {i} — wrong answer"
        return passed, len(cases), first_fail

    return 0, 0, f"unknown test.kind: {m.test_kind!r}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    cwd = Path.cwd()
    if not os.path.isfile(args.code):
        print(f"COMPILE_ERROR: file not found: {args.code}")
        sys.exit(1)

    # ---------------- Manifest path ----------------
    manifest = BuildManifest.from_dir(cwd)
    if manifest is not None:
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = os.path.join(tmpdir, "solution")
            ok, err = _manifest_compile(manifest, args.code, binary)
            if not ok:
                print(f"COMPILE_ERROR:\n{err[:1500]}")
                sys.exit(1)
            passed, total, first_fail = _run_manifest_tests(
                manifest, binary, timeout=max(args.timeout, manifest.test_timeout)
            )

        if total == 0:
            print(f"ERROR: no tests defined in build.yaml (test.kind={manifest.test_kind!r})")
            sys.exit(1)
        if passed == total:
            print("PASS")
            sys.exit(0)
        msg = f"FAIL — {passed}/{total} tests passed."
        if first_fail:
            msg += f" First failure: {first_fail}."
        print(msg)
        sys.exit(1)

    # ---------------- Legacy (leetcode) path ----------------
    slug = cwd.name.replace("repository_", "")
    attacker_dir = HERE
    map_path = os.path.join(attacker_dir, "experiments", "problem_map.json")
    data_path = os.environ.get(
        "DATA_PATH",
        os.path.join(attacker_dir, "data", "cpp_pointer_problems.jsonl"),
    )

    # Prefer local tests/ directory
    local_tests_dir = cwd / "tests"
    tests: list[tuple[str, str]] = []
    if local_tests_dir.is_dir():
        i = 0
        while True:
            inp_f = local_tests_dir / f"input_{i}.txt"
            out_f = local_tests_dir / f"output_{i}.txt"
            if not inp_f.is_file() or not out_f.is_file():
                break
            tests.append((inp_f.read_text(), out_f.read_text()))
            i += 1
    else:
        run_dir_map = cwd.parent / "problem_map.json"
        map_path = str(run_dir_map) if run_dir_map.is_file() else map_path
        problem = _find_problem(slug, map_path, data_path)
        if problem is None:
            print(f"ERROR: could not find problem for slug '{slug}'")
            sys.exit(1)
        for split in ("public_tests", "private_tests"):
            t = problem.get(split, {})
            tests.extend(zip(t.get("input", []), t.get("output", [])))

    if not tests:
        print("ERROR: no tests found for this problem")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        binary = os.path.join(tmpdir, "solution")
        ok, err = _legacy_compile(args.code, binary)
        if not ok:
            print(f"COMPILE_ERROR:\n{err}")
            sys.exit(1)

        passed = 0
        first_fail = None
        for i, (inp, expected) in enumerate(tests):
            actual, runtime_err, timed_out = _run_binary(binary, inp, args.timeout)
            if timed_out:
                first_fail = first_fail or f"test {i} — TIMEOUT"
            elif runtime_err:
                first_fail = first_fail or f"test {i} — RUNTIME_ERROR"
            elif actual == expected.rstrip():
                passed += 1
            else:
                first_fail = first_fail or f"test {i} — wrong answer"

    n = len(tests)
    if passed == n:
        print("PASS")
        sys.exit(0)
    msg = f"FAIL — {passed}/{n} tests passed."
    if first_fail:
        msg += f" First failure: {first_fail}."
    print(msg)
    sys.exit(1)


if __name__ == "__main__":
    main()
