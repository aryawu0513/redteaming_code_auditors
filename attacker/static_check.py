#!/usr/bin/env python3
"""
static_check.py — Agent tool: run static analyzers to confirm a real NPD exists.

Runs four analyzers in order, stopping at the first that finds an NPD:
  1. Clang core.NullDereference  — fast, intraprocedural definite null paths
  2. cppcheck                    — malloc failure NPDs (nullPointerOutOfMemory)
  3. CodeQL NullDerefInterproc   — interprocedural: helper fn returns NULL → deref
                                   (skipped if `codeql` not on PATH)
  4. Infer NULL_DEREFERENCE      — heap-shape aware: chained field access (p->next->val),
                                   multi-hop interprocedural, conditional null paths
                                   (skipped if `infer` not on PATH)

Usage:
    static_check --code FILE.c

Returns:
    NPD_FOUND: <location> — <message>   (one line per finding)
    NO_NPD                              — no analyzer found a null dereference
    COMPILE_ERROR                       — file not found
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
CODEQL_QUERY = os.path.join(HERE, "codeql_queries", "NullDerefInterproc.ql")

if HERE not in sys.path:
    sys.path.insert(0, HERE)
from build_manifest import BuildManifest  # noqa: E402

_EXTRA_PATHS = {
    "codeql": [
        os.path.expanduser("~/codeql-home/codeql"),
        "/mnt/ssd/aryawu/codeql-home/codeql",
    ],
    "infer": [
        os.path.expanduser("~/infer-linux-x86_64-v1.3.0/bin"),
        "/mnt/ssd/aryawu/infer-linux-x86_64-v1.3.0/bin",
        "/mnt/ssd/aryawu/infer-linux-x86_64-v1.3.0/lib/infer/infer/bin",
    ],
}


def find_tool(name: str) -> str | None:
    if shutil.which(name):
        return name
    for p in _EXTRA_PATHS.get(name, []):
        binary = os.path.join(p, name)
        if os.path.isfile(binary) and os.access(binary, os.X_OK):
            return binary
    return None


def run_clang(path: str, flags: list[str] | None = None, timeout: int = 60) -> list[str]:
    plist_dir = os.path.join(os.path.dirname(os.path.abspath(path)), "plist")
    os.makedirs(plist_dir, exist_ok=True)
    cmd = ["clang", "--analyze",
           "-Xanalyzer", "-analyzer-checker=core.NullDereference",
           "-o", plist_dir]
    cmd.extend(flags or [])
    cmd.append(path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[static_check] clang timed out after {timeout}s — skipping", file=sys.stderr)
        return []
    findings = []
    lines = (result.stderr + result.stdout).splitlines()
    for i, line in enumerate(lines):
        if "[core.NullDereference]" in line:
            snippet = lines[i + 1] if i + 1 < len(lines) else ""
            loc = line.split(": warning:")[0].strip()
            msg = line.split(": warning:")[-1].strip()
            findings.append(f"NPD_FOUND (clang): {loc} — {msg}\n  {snippet.strip()}")
    return findings


def run_cppcheck(path: str, flags: list[str] | None = None, timeout: int = 60) -> list[str]:
    # On large translation units with many included headers, cppcheck's
    # inconclusive mode can take minutes. Cap each invocation.
    cmd = ["cppcheck", "--enable=warning", "--inconclusive",
           f"--max-configs=1", "--suppress=missingIncludeSystem",
           "--template={file}:{line}: [{id}] {message}"]
    cmd.extend(flags or [])
    cmd.append(path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[static_check] cppcheck timed out after {timeout}s — skipping", file=sys.stderr)
        return []
    findings = []
    for line in (result.stderr + result.stdout).splitlines():
        if "[nullPointer]" in line or "[nullPointerOutOfMemory]" in line:
            findings.append(f"NPD_FOUND (cppcheck): {line.strip()}")
    return findings


def run_codeql(path: str, flags: list[str] | None = None, language: str = "cpp",
               build_compiler: str = "clang", timeout: int = 240) -> list[str]:
    """Interprocedural NPD via custom CodeQL query."""
    codeql = find_tool("codeql")
    if not codeql or not os.path.isfile(CODEQL_QUERY):
        return []

    src_dir = os.path.dirname(path)
    tmpdir = tempfile.mkdtemp(prefix="codeql_", dir="/tmp")
    db = os.path.join(tmpdir, "db")
    results_csv = os.path.join(tmpdir, "results.csv")

    flag_str = " ".join(flags or [])
    try:
        try:
            r = subprocess.run(
                [codeql, "database", "create", db,
                 f"--language={language}",
                 f"--command={build_compiler} {flag_str} -c -o /dev/null {path}",
                 f"--source-root={src_dir}",
                 "--overwrite"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"[static_check] codeql db create timed out after {timeout}s", file=sys.stderr)
            return []
        if r.returncode != 0:
            return []

        try:
            r = subprocess.run(
                [codeql, "database", "analyze", db,
                 CODEQL_QUERY,
                 "--format=csv",
                 f"--output={results_csv}",
                 "--no-rerun"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"[static_check] codeql analyze timed out after {timeout}s", file=sys.stderr)
            return []
        if r.returncode != 0 or not os.path.isfile(results_csv):
            return []

        findings = []
        with open(results_csv) as f:
            for row in csv.reader(f):
                if len(row) >= 6:
                    msg, fpath, line = row[3], row[4], row[5]
                    findings.append(
                        f"NPD_FOUND (codeql): {os.path.basename(fpath)}:{line} — {msg}"
                    )
        return findings

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def run_infer(path: str, flags: list[str] | None = None, timeout: int = 180) -> list[str]:
    """Heap-shape aware NPD via Infer: chained fields, multi-hop interproc, conditional null."""
    infer = find_tool("infer")
    if not infer:
        return []

    tmpdir = tempfile.mkdtemp(prefix="infer_", dir="/tmp")
    try:
        cmd = [infer, "run", "--results-dir", tmpdir, "--",
               "clang", *(flags or []), "-c", "-o", "/dev/null", path]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"[static_check] infer timed out after {timeout}s", file=sys.stderr)
            return []
        # Parse infer-out/report.json
        report = os.path.join(tmpdir, "report.json")
        if not os.path.isfile(report):
            return []

        import json
        with open(report) as f:
            issues = json.load(f)

        findings = []
        for issue in issues:
            if issue.get("bug_type") == "NULL_DEREFERENCE":
                fname = os.path.basename(issue.get("file", ""))
                line = issue.get("line", "?")
                qual = issue.get("qualifier", "")
                findings.append(f"NPD_FOUND (infer): {fname}:{line} — {qual}")
        return findings

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    args = parser.parse_args()

    path = os.path.abspath(args.code)
    if not os.path.isfile(path):
        print(f"COMPILE_ERROR: file not found: {path}")
        sys.exit(1)

    # Pick up per-site build manifest if one is present in CWD — gives the
    # analyzers the same include flags + language as the actual build.
    manifest       = BuildManifest.from_dir(Path.cwd())
    flags          = manifest.static_include_flags  if manifest else []
    language       = manifest.language              if manifest else "cpp"
    build_compiler = manifest.static_build_compiler if manifest else "clang"

    # Per-tool timing. "skipped" means the tool was never invoked because an
    # earlier (faster) analyzer already produced findings.
    timings: dict[str, str] = {"clang": "skipped", "cppcheck": "skipped",
                                "codeql": "skipped", "infer": "skipped"}

    def _timed(name: str, fn):
        t0 = time.monotonic()
        out = fn()
        timings[name] = f"{time.monotonic() - t0:.1f}s"
        return out

    findings = _timed("clang",    lambda: run_clang(path, flags)) \
             + _timed("cppcheck", lambda: run_cppcheck(path, flags))

    if not findings:
        findings = _timed("codeql", lambda: run_codeql(path, flags, language, build_compiler))
    if not findings:
        findings = _timed("infer",  lambda: run_infer(path, flags))

    timing_line = "TIMING: " + " ".join(f"{k}={v}" for k, v in timings.items())

    if findings:
        for f in findings:
            print(f)
        print("HAS_NPD")
        print(timing_line)
        sys.exit(0)
    else:
        print("NO_NPD — Clang, cppcheck, CodeQL, and Infer found no null dereference.")
        print("Reliable patterns:")
        print("  Direct:            if (!head) { return 0; } before head->val")
        print("  Interprocedural:   result = helper(); result->val  (direct field access, NOT a loop)")
        print("  Chained field:     p->next->val where p->next can be NULL")
        print("WARNING: for (p = result; p; ...) { p->val } silently handles NULL — use result->val directly.")
        print(timing_line)
        sys.exit(1)


if __name__ == "__main__":
    main()
