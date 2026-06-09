#!/usr/bin/env python3
"""
Run static analysis (Clang + cppcheck + CodeQL + Infer via static_check.py)
on context.cc for each CVE sample and produce a summary table.

Usage:
    python3 run_static_analysis_cve.py [NPD-CVE-01 ...] [--samples-dir DIR]

Output:
    JSON results written to samples_dir/<pid>/static_analysis.json
    Summary table printed to stdout.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

HERE            = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve"
STATIC_CHECK    = Path(__file__).parents[1] / "attacker" / "static_check.py"


def run_analysis(pid: str, samples_dir: Path) -> dict:
    out_dir    = samples_dir / pid
    context_cc = out_dir / "context.cc"
    if not context_cc.exists():
        return {"pid": pid, "status": "missing", "found": False, "tool": None, "findings": []}

    t0 = time.monotonic()
    r = subprocess.run(
        [sys.executable, str(STATIC_CHECK), "--code", str(context_cc)],
        capture_output=True, text=True, timeout=300,
    )
    elapsed = time.monotonic() - t0

    stdout = r.stdout
    found  = "HAS_NPD" in stdout
    tool   = None
    findings = []

    for line in stdout.splitlines():
        if line.startswith("NPD_FOUND"):
            findings.append(line)
            # parse tool name: "NPD_FOUND (clang): ..." → "clang"
            if tool is None and "(" in line and ")" in line:
                tool = line.split("(")[1].split(")")[0]

    timing_line = next((l for l in stdout.splitlines() if l.startswith("TIMING:")), "")

    result = {
        "pid":      pid,
        "status":   "found" if found else "not_found",
        "found":    found,
        "tool":     tool,
        "findings": findings,
        "timing":   timing_line,
        "elapsed":  round(elapsed, 1),
    }
    (out_dir / "static_analysis.json").write_text(json.dumps(result, indent=2))
    return result


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", help="Pilot IDs (default: all NPD-CVE-* dirs)")
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES))
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    if args.ids:
        pids = args.ids
    else:
        pids = sorted(p.name for p in samples_dir.glob("NPD-CVE-*") if p.is_dir())

    if not pids:
        print(f"No samples found in {samples_dir}")
        sys.exit(1)

    print(f"Running static analysis on {len(pids)} samples in {samples_dir}/\n")
    print(f"{'PID':<15} {'Result':<12} {'Tool':<10} {'Elapsed':>8}  Findings")
    print("-" * 75)

    results = []
    for pid in pids:
        print(f"  {pid}...", end=" ", flush=True)
        try:
            res = run_analysis(pid, samples_dir)
        except subprocess.TimeoutExpired:
            res = {"pid": pid, "status": "timeout", "found": False, "tool": None,
                   "findings": [], "timing": "", "elapsed": 300.0}
        except Exception as e:
            res = {"pid": pid, "status": f"error: {e}", "found": False, "tool": None,
                   "findings": [], "timing": "", "elapsed": 0.0}
        results.append(res)
        icon   = "✓ HAS_NPD" if res["found"] else "✗ NO_NPD "
        tool   = res.get("tool") or "-"
        elapsed = res.get("elapsed", 0)
        first  = res["findings"][0][:60] if res["findings"] else ""
        print(f"\r{pid:<15} {icon:<12} {tool:<10} {elapsed:>7.1f}s  {first}")

    print("-" * 75)
    found_count = sum(1 for r in results if r["found"])
    print(f"\nSummary: {found_count}/{len(results)} samples have statically detectable NPD\n")

    # Per-tool breakdown
    tool_counts: dict[str, int] = {}
    for r in results:
        if r["found"] and r["tool"]:
            tool_counts[r["tool"]] = tool_counts.get(r["tool"], 0) + 1
    if tool_counts:
        print("By tool:")
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            print(f"  {tool:<10}: {count}")

    # Print IDs not found
    not_found = [r["pid"] for r in results if not r["found"]]
    if not_found:
        print(f"\nNot detected: {', '.join(not_found)}")


if __name__ == "__main__":
    main()
