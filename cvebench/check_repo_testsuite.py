#!/usr/bin/env python3
"""
check_repo_testsuite.py — Stage 1 Step 1: verify repo builds and tests pass at fix commit.

For each repo (not each sample), at the fix commit:
  1. Clone repo into --clone-dir
  2. Run config heuristics so the build system is ready
  3. Full build: make -j4 (or cmake --build)
  4. Run test suite: tries ctest / make check / make test in order
  5. Write per-sample sentinel: repo_testsuite_pass / _partial / _fail / _none

A "pass" means the repo's own tests pass at the fix commit, confirming the
fix is real and the repo is healthy. "partial" means the suite ran but had
some failures (network-dependent tests, missing hardware, etc.).

This is much slower than check_repo_compilable.py — expect minutes per repo.

Usage:
  python3 cvebench/check_repo_testsuite.py \\
      cvebench/f3_nolimit_dedup_func.jsonl \\
      [--samples-dir cvebench/samples_cve_fix] \\
      [--clone-dir /tmp/cve_repos_fix] \\
      [--build-timeout 600] [--test-timeout 300] \\
      [--skip-repos torvalds/linux xen-project/xen] \\
      [--out results_testsuite.json]

Outputs per sample dir:
  repo_testsuite_pass      — suite ran, all tests passed (or suite said OK)
  repo_testsuite_partial   — suite ran, some tests failed (flaky/env-dependent)
  repo_testsuite_fail      — build or suite invocation failed entirely
  repo_testsuite_none      — no recognizable test suite found
  repo_testsuite_result    — JSON with build_ok, suite_cmd, returncode, summary
"""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

# Use system cmake directly — the cmake in PATH on this machine is a broken
# Python wrapper; /usr/bin/cmake is the real CMake 3.22.
CMAKE = "/usr/bin/cmake"

HERE = Path(__file__).parent

DEFAULT_SKIP = {
    "torvalds/linux",
    "xen-project/xen",
    "qemu/qemu",
    "tensorflow/tensorflow",
    "chromium/chromium",
}

BUILD_TIMEOUT = 600   # seconds for full build
TEST_TIMEOUT  = 300   # seconds for test suite run


# ---------------------------------------------------------------------------
# Clone (reuses existing clone from check_repo_compilable run)
# ---------------------------------------------------------------------------

def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


def clone_repo(url: str, clone_dir: Path, commit: str) -> Path | None:
    dest = clone_dir / repo_slug(url)
    if (dest / ".git").exists():
        print(f"  [cached clone] {url}")
        return dest

    print(f"  Cloning {url} …")
    try:
        r = subprocess.run(
            ["git", "clone", "--filter=blob:none", url, str(dest)],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        print(f"    CLONE TIMEOUT — skipping")
        shutil.rmtree(dest, ignore_errors=True)
        return None
    except Exception as e:
        print(f"    CLONE ERROR: {e}")
        shutil.rmtree(dest, ignore_errors=True)
        return None

    if r.returncode != 0:
        msg = r.stderr.splitlines()[0][:120] if r.stderr else "(no output)"
        print(f"    CLONE FAIL: {msg}")
        shutil.rmtree(dest, ignore_errors=True)
        return None

    for ref in [commit, "HEAD"]:
        try:
            r = subprocess.run(["git", "-C", str(dest), "checkout", ref],
                               capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            continue
        if r.returncode == 0:
            print(f"    checked out {ref}")
            (dest / ".checked_out_ref").write_text(ref)
            return dest

    print(f"    FAIL: could not checkout any ref")
    shutil.rmtree(dest, ignore_errors=True)
    return None


# ---------------------------------------------------------------------------
# Config generation (same heuristics as check_repo_compilable.py)
# ---------------------------------------------------------------------------

def run_config(repo_path: Path, file_path: str) -> None:
    def run(cmd, cwd=None, timeout=180):
        try:
            return subprocess.run(cmd, cwd=str(cwd or repo_path),
                                  capture_output=True, text=True, timeout=timeout)
        except Exception:
            return None

    file_dir = (repo_path / file_path).parent
    ran = []

    for d in [file_dir, repo_path]:
        gs = d / "genconfig.sh"
        if gs.exists():
            r = run(["bash", "genconfig.sh"], cwd=d, timeout=60)
            ran.append(f"genconfig({'OK' if r and r.returncode==0 else 'partial'})")
            break

    if (repo_path / "configure.ac").exists() and not (repo_path / "configure").exists():
        run(["autoreconf", "-fi"], timeout=120)
        ran.append("autoreconf")

    if (repo_path / "autogen.sh").exists():
        run(["bash", "autogen.sh"], timeout=120)
        ran.append("autogen.sh")

    if (repo_path / "configure").exists():
        r = run(["./configure", "--quiet"], timeout=180)
        ran.append(f"./configure({'OK' if r and r.returncode==0 else 'partial'})")

    if (repo_path / "CMakeLists.txt").exists():
        build_dir = repo_path / "_cmake_build"
        build_dir.mkdir(exist_ok=True)
        r = run([CMAKE, "-S", str(repo_path), "-B", str(build_dir),
                 "-DCMAKE_BUILD_TYPE=Debug", "-DBUILD_TESTING=ON",
                 "--no-warn-unused-cli"], timeout=180)
        ran.append(f"cmake({'OK' if r and r.returncode==0 else 'partial'})")

    if ran:
        print(f"    config: {' → '.join(ran)}")


# ---------------------------------------------------------------------------
# Full build
# ---------------------------------------------------------------------------

def run_full_build(repo_path: Path, build_timeout: int) -> tuple[bool, str]:
    """Run a full build so test binaries exist. Returns (ok, summary)."""
    def run(cmd, cwd=None):
        try:
            r = subprocess.run(cmd, cwd=str(cwd or repo_path),
                               capture_output=True, text=True, timeout=build_timeout)
            return r
        except subprocess.TimeoutExpired:
            return None

    cmake_build = repo_path / "_cmake_build"

    # CMake build
    if cmake_build.exists():
        r = run([CMAKE, "--build", str(cmake_build), "--parallel", "4"])
        if r is None:
            return False, "cmake build timeout"
        if r.returncode == 0:
            print(f"    full build: cmake OK")
            return True, "cmake --build OK"
        # Don't give up — may still have built enough for tests
        print(f"    full build: cmake partial (rc={r.returncode})")
        return True, f"cmake --build partial rc={r.returncode}"

    # Makefile build
    if (repo_path / "Makefile").exists():
        r = run(["make", "-j4", "-k", "--keep-going"])
        if r is None:
            return False, "make timeout"
        if r.returncode == 0:
            print(f"    full build: make OK")
            return True, "make OK"
        # Partial build is common and often enough for tests
        print(f"    full build: make partial (rc={r.returncode})")
        return True, f"make partial rc={r.returncode}"

    return False, "no build system found (no Makefile, no _cmake_build)"


# ---------------------------------------------------------------------------
# Test suite detection and execution
# ---------------------------------------------------------------------------

def _parse_test_summary(output: str, returncode: int) -> tuple[str, str]:
    """Classify test run as pass / partial / fail and extract a short summary line."""
    combined = (output or "")

    # ctest summary line: e.g. "100% tests passed, 0 tests failed out of 5"
    m = re.search(r'(\d+)% tests passed.*?out of (\d+)', combined)
    if m:
        pct, total = int(m.group(1)), int(m.group(2))
        line = m.group(0)
        if pct == 100:
            return "pass", line
        if pct >= 50:
            return "partial", line
        return "fail", line

    # automake summary: "# PASS: N" / "# FAIL: N"
    passes = sum(int(x) for x in re.findall(r'# PASS:\s*(\d+)', combined))
    fails  = sum(int(x) for x in re.findall(r'# FAIL:\s*(\d+)', combined))
    if passes or fails:
        line = f"PASS={passes} FAIL={fails}"
        if fails == 0:
            return "pass", line
        if passes > 0:
            return "partial", line
        return "fail", line

    # Generic: look for "N tests passed" / "N failures"
    m = re.search(r'(\d+) (?:test[s]? passed|passed)', combined, re.I)
    if m and returncode == 0:
        return "pass", m.group(0)

    # Fall back to exit code
    if returncode == 0:
        return "pass", "exit 0"
    return "fail", f"exit {returncode}"


def _extract_failures(output: str) -> list[str]:
    """Extract just the failing test names from test output."""
    lines = (output or "").splitlines()
    failures = [l for l in lines if re.match(r'^(FAIL|FAILED|ERROR)[\s:]', l)]
    # ctest failure format: "N - TestName (Failed)"
    failures += [l for l in lines if re.search(r'\(Failed\)', l)]
    return failures[:50]  # cap at 50


def _makefile_declares_target(mf_text: str, target: str) -> bool:
    """True if `target` appears as one of the (possibly several) space-separated
    target names on a rule line, e.g. 'test check: unittests ...' declares both
    'test' and 'check'. Only matches unindented, non-comment lines (rule
    headers, not recipes or comments like '# - check the output:')."""
    for line in mf_text.splitlines():
        if not line or line[0].isspace():
            continue  # indented lines are recipe commands, not rule headers
        if line.lstrip().startswith("#"):
            continue  # comment line, even one containing ':'
        if ":" not in line:
            continue
        lhs = line.split(":", 1)[0]
        if target in lhs.split():
            return True
    return False


def _candidate_makefile_dirs(repo_path: Path, file_paths: list[str]) -> list[Path]:
    """Dirs to look for a Makefile with a test target, root-first: the repo
    root is checked first since a project-wide `make check` there is the
    canonical test entrypoint; only if root has no target do we fall back to
    subdirectories derived from every sample's file_path in this repo group
    (not just one), since samples can live under different top-level dirs
    (e.g. ImageMagick's MagickCore/ vs coders/). Some projects (e.g. vim)
    keep their real build/test Makefile in a subdirectory, not at the root."""
    dirs: list[Path] = [repo_path]
    seen = {repo_path}
    top_subdirs: list[Path] = []
    file_dirs: list[Path] = []
    for fp in file_paths:
        if not fp:
            continue
        rel = Path(fp)
        if len(rel.parts) > 1:
            top_subdirs.append(repo_path / rel.parts[0])
        file_dirs.append(repo_path / rel.parent)
    for d in top_subdirs + file_dirs:
        if d not in seen:
            seen.add(d)
            dirs.append(d)
    return dirs


def run_testsuite(repo_path: Path, test_timeout: int, file_paths: list[str] | None = None) -> dict:
    """Try make test / make check / ctest. Returns result dict."""
    cmake_build = repo_path / "_cmake_build"

    def run(cmd, cwd=None):
        try:
            r = subprocess.run(cmd, cwd=str(cwd or repo_path),
                               capture_output=True, text=True, timeout=test_timeout)
            return r
        except subprocess.TimeoutExpired:
            return None

    # ── ctest ────────────────────────────────────────────────────────────────
    ctest = Path(CMAKE).parent / "ctest"
    if cmake_build.exists() and ctest.exists():
        r = run([str(ctest), "--test-dir", str(cmake_build), "--output-on-failure",
                 "-j4", "--timeout", str(test_timeout // 2)])
        if r is not None:
            combined = r.stdout + r.stderr
            verdict, summary = _parse_test_summary(combined, r.returncode)
            print(f"    ctest: {verdict}  ({summary})")
            return {"suite_cmd": "ctest", "returncode": r.returncode,
                    "verdict": verdict, "summary": summary,
                    "failed_tests": _extract_failures(combined)}
        print(f"    ctest: timeout")
        return {"suite_cmd": "ctest", "returncode": -1,
                "verdict": "fail", "summary": "timeout", "failed_tests": []}

    # ── make check ───────────────────────────────────────────────────────────
    for mf_dir in _candidate_makefile_dirs(repo_path, file_paths or []):
        makefile = mf_dir / "Makefile"
        if not makefile.exists():
            continue
        mf_text = makefile.read_text(errors="replace")
        for target in ("check", "test", "tests"):
            if not _makefile_declares_target(mf_text, target):
                continue
            r = run(["make", target, "-k", "--keep-going"], cwd=mf_dir)
            if r is None:
                print(f"    make {target} ({mf_dir}): timeout")
                return {"suite_cmd": f"make {target}", "returncode": -1,
                        "verdict": "fail", "summary": "timeout", "failed_tests": []}
            combined = r.stdout + r.stderr
            verdict, summary = _parse_test_summary(combined, r.returncode)
            print(f"    make {target} ({mf_dir}): {verdict}  ({summary})")
            return {"suite_cmd": f"make {target} ({mf_dir})", "returncode": r.returncode,
                    "verdict": verdict, "summary": summary,
                    "failed_tests": _extract_failures(combined)}

    print(f"    no test suite found")
    return {"suite_cmd": None, "returncode": None,
            "verdict": "none", "summary": "no test target found", "failed_tests": []}


# ---------------------------------------------------------------------------
# Write per-sample output
# ---------------------------------------------------------------------------

def write_sample_result(sample_dir: Path, build_ok: bool, build_summary: str,
                        suite: dict) -> None:
    verdict = suite["verdict"]   # pass / partial / fail / none

    # Remove old sentinels
    for name in ("repo_testsuite_pass", "repo_testsuite_partial",
                 "repo_testsuite_fail", "repo_testsuite_none"):
        (sample_dir / name).unlink(missing_ok=True)

    if not build_ok:
        (sample_dir / "repo_testsuite_fail").touch()
        verdict = "fail"
    else:
        (sample_dir / f"repo_testsuite_{verdict}").touch()

    result = {
        "build_ok":     build_ok,
        "build_summary": build_summary,
        "suite_cmd":    suite.get("suite_cmd"),
        "returncode":   suite.get("returncode"),
        "verdict":      verdict,
        "summary":      suite.get("summary", ""),
    }
    (sample_dir / "repo_testsuite_result").write_text(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("jsonl")
    ap.add_argument("--samples-dir",    default=str(HERE / "samples_cve_fix"))
    ap.add_argument("--clone-dir",      default="/tmp/cve_repos_fix")
    ap.add_argument("--build-timeout",  type=int, default=BUILD_TIMEOUT)
    ap.add_argument("--test-timeout",   type=int, default=TEST_TIMEOUT)
    ap.add_argument("--skip-repos",     nargs="*", default=list(DEFAULT_SKIP))
    ap.add_argument("--out",            default=None)
    args = ap.parse_args()

    samples_dir   = Path(args.samples_dir)
    clone_dir     = Path(args.clone_dir)
    clone_dir.mkdir(parents=True, exist_ok=True)
    skip_repos    = set(args.skip_repos)
    out_path      = (Path(args.out) if args.out
                     else samples_dir / "step_testsuite.json")

    rows = [json.loads(l) for l in Path(args.jsonl).read_text().splitlines() if l.strip()]

    # Group by repo — run build+tests once per repo
    by_repo: dict[str, list[dict]] = {}
    for row in rows:
        url  = row.get("repo_url", "")
        slug = url.replace("https://github.com/", "")
        if url:
            by_repo.setdefault(slug, []).append(row)

    print(f"Repos: {len(by_repo)}  |  Skip: {len(skip_repos)}")
    print(f"Samples dir: {samples_dir}")
    print(f"Clone dir:   {clone_dir}\n")

    counts: dict[str, int] = {}
    all_results: list[dict] = []

    for slug, repo_rows in sorted(by_repo.items(), key=lambda x: -len(x[1])):
        print(f"\n{'='*60}")
        print(f"{slug}  ({len(repo_rows)} samples)")

        if slug in skip_repos:
            print(f"  [SKIP]")
            for row in repo_rows:
                all_results.append({"pid": row["pilot_id"], "outcome": "repo_skip", "repo": slug})
            counts["repo_skip"] = counts.get("repo_skip", 0) + len(repo_rows)
            continue

        commits = [r.get("commit_hash", "") for r in repo_rows if r.get("commit_hash")]
        commit  = commits[0] if commits else "HEAD"
        url     = f"https://github.com/{slug}"

        repo_path = clone_repo(url, clone_dir, commit)
        if repo_path is None:
            for row in repo_rows:
                all_results.append({"pid": row["pilot_id"], "outcome": "clone_fail", "repo": slug})
            counts["clone_fail"] = counts.get("clone_fail", 0) + len(repo_rows)
            continue

        # Config + full build (once per repo)
        file_path = repo_rows[0].get("file_path") or repo_rows[0].get("file", "")
        run_config(repo_path, file_path)
        build_ok, build_summary = run_full_build(repo_path, args.build_timeout)

        # Test suite (once per repo) — check every sample's file_path, not just
        # row 0, since a repo's CVE-touched files can span multiple top-level
        # dirs (e.g. ImageMagick: MagickCore/ vs coders/).
        all_file_paths = [r.get("file_path") or r.get("file", "") for r in repo_rows]
        suite = run_testsuite(repo_path, args.test_timeout, file_paths=all_file_paths)
        verdict = suite["verdict"] if build_ok else "fail"

        # Apply result to all samples from this repo
        for row in repo_rows:
            pid        = row["pilot_id"]
            sample_dir = samples_dir / pid
            sample_dir.mkdir(parents=True, exist_ok=True)
            write_sample_result(sample_dir, build_ok, build_summary, suite)
            print(f"    {pid}: {verdict}  ({suite.get('summary','')})")
            all_results.append({
                "pid":          pid,
                "outcome":      f"testsuite_{verdict}",
                "repo":         slug,
                "build_ok":     build_ok,
                "suite_cmd":    suite.get("suite_cmd"),
                "suite_verdict": verdict,
                "summary":      suite.get("summary", ""),
            })
            counts[f"testsuite_{verdict}"] = counts.get(f"testsuite_{verdict}", 0) + 1

    out_path.write_text(json.dumps(all_results, indent=2))
    print(f"\nResults → {out_path}")
    print(f"\n{'='*60}\nSummary:")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {k:30s}: {v}")
    n_pass = counts.get("testsuite_pass", 0) + counts.get("testsuite_partial", 0)
    print(f"\n  testsuite ran (pass+partial): {n_pass}")


if __name__ == "__main__":
    main()
