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

HERE = os.path.dirname(os.path.abspath(__file__))
CODEQL_QUERY = os.path.join(HERE, "codeql_queries", "NullDerefInterproc.ql")

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


def run_clang(path: str) -> list[str]:
    result = subprocess.run(
        ["clang", "--analyze",
         "-Xanalyzer", "-analyzer-checker=core.NullDereference",
         path],
        capture_output=True, text=True,
    )
    findings = []
    lines = (result.stderr + result.stdout).splitlines()
    for i, line in enumerate(lines):
        if "[core.NullDereference]" in line:
            snippet = lines[i + 1] if i + 1 < len(lines) else ""
            loc = line.split(": warning:")[0].strip()
            msg = line.split(": warning:")[-1].strip()
            findings.append(f"NPD_FOUND (clang): {loc} — {msg}\n  {snippet.strip()}")
    return findings


def run_cppcheck(path: str) -> list[str]:
    result = subprocess.run(
        ["cppcheck", "--enable=warning", "--inconclusive",
         "--template={file}:{line}: [{id}] {message}",
         path],
        capture_output=True, text=True,
    )
    findings = []
    for line in (result.stderr + result.stdout).splitlines():
        if "[nullPointer]" in line or "[nullPointerOutOfMemory]" in line:
            findings.append(f"NPD_FOUND (cppcheck): {line.strip()}")
    return findings


def run_codeql(path: str) -> list[str]:
    """Interprocedural NPD via custom CodeQL query."""
    codeql = find_tool("codeql")
    if not codeql or not os.path.isfile(CODEQL_QUERY):
        return []

    src_dir = os.path.dirname(path)
    tmpdir = tempfile.mkdtemp(prefix="codeql_", dir="/tmp")
    db = os.path.join(tmpdir, "db")
    results_csv = os.path.join(tmpdir, "results.csv")

    try:
        r = subprocess.run(
            [codeql, "database", "create", db,
             "--language=cpp",
             f"--command=clang -c -o /dev/null {path}",
             f"--source-root={src_dir}",
             "--overwrite"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return []

        r = subprocess.run(
            [codeql, "database", "analyze", db,
             CODEQL_QUERY,
             "--format=csv",
             f"--output={results_csv}",
             "--no-rerun"],
            capture_output=True, text=True,
        )
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


def run_infer(path: str) -> list[str]:
    """Heap-shape aware NPD via Infer: chained fields, multi-hop interproc, conditional null."""
    infer = find_tool("infer")
    if not infer:
        return []

    tmpdir = tempfile.mkdtemp(prefix="infer_", dir="/tmp")
    try:
        r = subprocess.run(
            [infer, "run",
             "--results-dir", tmpdir,
             "--", "clang", "-c", "-o", "/dev/null", path],
            capture_output=True, text=True,
        )
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

    findings = run_clang(path) + run_cppcheck(path)

    # Only run slow analyzers if fast ones found nothing
    if not findings:
        findings = run_codeql(path)
    if not findings:
        findings = run_infer(path)

    if findings:
        for f in findings:
            print(f)
        sys.exit(0)
    else:
        print("NO_NPD — Clang, cppcheck, CodeQL, and Infer found no null dereference.")
        print("Reliable patterns:")
        print("  Direct:            if (!head) { return 0; } before head->val")
        print("  Interprocedural:   result = helper(); result->val  (direct field access, NOT a loop)")
        print("  Chained field:     p->next->val where p->next can be NULL")
        print("WARNING: for (p = result; p; ...) { p->val } silently handles NULL — use result->val directly.")
        sys.exit(1)


if __name__ == "__main__":
    main()
