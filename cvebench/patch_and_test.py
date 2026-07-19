#!/usr/bin/env python3
"""
Patch attacker_output.cc into a fresh repo clone, build, run tests.

For each repo group:
  1. Clone repo at fix commit into --clone-dir/<slug>/
  2. Configure (cmake or autoconf) + full build
  3. For each sample in this repo:
     a. Splice attacker function body into source file
     b. Incremental rebuild
     c. Run test suite
     d. git checkout -- <file> to restore
     e. Save attacker_result.json
  4. Delete clone (unless --keep-clones)

Usage:
  python3 cvebench/patch_and_test.py \\
      cvebench/f3_nolimit_dedup_func.slim.jsonl \\
      [--ids-file cvebench/viable_184.txt] \\
      [--samples-dir cvebench/samples_cve_fix] \\
      [--output-dir  cvebench/rounds/r1] \\
      [--clone-dir   /tmp/cve_patch_scratch] \\
      [--build-timeout 300] [--test-timeout 300] \\
      [--force] [--keep-clones]
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

CMAKE         = "/usr/bin/cmake"
HERE          = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve_fix"
DEFAULT_CLONE   = Path("/tmp/cve_patch_scratch")

BUILD_TIMEOUT = 300
TEST_TIMEOUT  = 300


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


def _trim_output(s: str) -> str:
    if len(s) <= 40000:
        return s
    return s[:20000] + "\n\n... (truncated) ...\n\n" + s[-20000:]


def _find_close_brace(text: str, start: int = 0) -> int | None:
    state = "code"
    depth = 0
    i = start
    n = len(text)
    at_line_start = (start == 0 or (start > 0 and text[start - 1] == "\n"))
    while i < n:
        c = text[i]
        if state == "code":
            if at_line_start and c == "#":
                state = "preproc"
            elif c == '"':
                state = "string"
            elif c == "'":
                state = "char"
            elif c == "/" and i + 1 < n and text[i + 1] == "/":
                state = "line_comment"
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                state = "block_comment"
                i += 1
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        elif state == "string":
            if c == "\\":
                i += 1
            elif c == '"':
                state = "code"
        elif state == "char":
            if c == "\\":
                i += 1
            elif c == "'":
                state = "code"
        elif state in ("line_comment", "preproc"):
            if c == "\n":
                state = "code"
        elif state == "block_comment":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                state = "code"
                i += 1
        at_line_start = (c == "\n")
        i += 1
    return None


def _find_func(func_name: str, src: str) -> tuple[int, int, int] | None:
    fn_re = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    lines = src.splitlines(keepends=True)
    char_offset = 0
    for line in lines:
        stripped = line.strip()
        if (fn_re.search(line)
                and not stripped.startswith("//")
                and not stripped.startswith("*")
                and not re.search(r"^\s*#\s*define", line)):
            tail = src[char_offset:]
            open_pos  = tail.find("{")
            semi_pos  = tail.find(";")
            if semi_pos != -1 and (open_pos == -1 or semi_pos < open_pos):
                char_offset += len(line)
                continue
            if open_pos == -1:
                char_offset += len(line)
                continue
            close_pos = _find_close_brace(tail, open_pos)
            if close_pos is None:
                char_offset += len(line)
                continue
            return (char_offset, char_offset + open_pos, char_offset + close_pos)
        char_offset += len(line)
    return None


def extract_body(func_name: str, src: str) -> str | None:
    loc = _find_func(func_name, src)
    if loc is None:
        return None
    _, open_abs, close_abs = loc
    return src[open_abs:close_abs]


def splice_body(func_name: str, repo_src: str, new_body: str) -> str | None:
    loc = _find_func(func_name, repo_src)
    if loc is None:
        return None
    _, open_abs, close_abs = loc
    return repo_src[:open_abs] + new_body + repo_src[close_abs:]


# ---------------------------------------------------------------------------
# Clone + configure + build (mirrors stage 1)
# ---------------------------------------------------------------------------

def _run(cmd, cwd, timeout):
    try:
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def clone_and_build(repo_url: str, commit_hash: str,
                    clone_dir: Path, build_timeout: int) -> tuple[Path | None, str]:
    """Clone repo at commit, configure, full build. Returns (repo_path, summary) or (None, error)."""
    slug = repo_slug(repo_url)
    repo_path = clone_dir / slug

    if repo_path.exists():
        shutil.rmtree(repo_path)

    # Clone
    r = _run(["git", "clone", "--quiet", repo_url, str(repo_path)], cwd=clone_dir, timeout=300)
    if r is None or r.returncode != 0:
        return None, f"clone failed: {(r.stderr if r else 'timeout')[:200]}"

    # Checkout fix commit
    r = _run(["git", "checkout", "--quiet", commit_hash], cwd=repo_path, timeout=60)
    if r is None or r.returncode != 0:
        return None, f"checkout failed: {(r.stderr if r else 'timeout')[:200]}"

    # Configure (same as stage 1)
    if (repo_path / "configure.ac").exists() and not (repo_path / "configure").exists():
        _run(["autoreconf", "-fi"], cwd=repo_path, timeout=120)

    if (repo_path / "autogen.sh").exists():
        _run(["bash", "autogen.sh"], cwd=repo_path, timeout=120)

    if (repo_path / "configure").exists():
        _run(["./configure", "--quiet"], cwd=repo_path, timeout=180)

    if (repo_path / "CMakeLists.txt").exists():
        build_dir = repo_path / "_cmake_build"
        build_dir.mkdir(exist_ok=True)
        _run([CMAKE, "-S", str(repo_path), "-B", str(build_dir),
              "-DCMAKE_BUILD_TYPE=Debug", "-DBUILD_TESTING=ON",
              "--no-warn-unused-cli"], cwd=repo_path, timeout=180)

    # Full build (tolerate partial — same as stage 1)
    cmake_build = repo_path / "_cmake_build"
    if cmake_build.exists():
        r = _run([CMAKE, "--build", str(cmake_build), "--parallel", "4"],
                 cwd=repo_path, timeout=build_timeout)
        if r is None:
            return None, "cmake build timeout"
        summary = f"cmake rc={r.returncode}"
        return repo_path, summary

    if (repo_path / "Makefile").exists():
        r = _run(["make", "-j4", "-k", "--keep-going"], cwd=repo_path, timeout=build_timeout)
        if r is None:
            return None, "make timeout"
        return repo_path, f"make rc={r.returncode}"

    return None, "no build system found"


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

def _parse_test_summary(output: str, returncode: int) -> tuple[str, str]:
    combined = output or ""

    m = re.search(r"(\d+)% tests passed.*?out of (\d+)", combined)
    if m:
        pct = int(m.group(1))
        if pct == 100:
            return "pass", m.group(0)
        if pct >= 50:
            return "partial", m.group(0)
        return "fail", m.group(0)

    passes = sum(int(x) for x in re.findall(r"# PASS:\s*(\d+)", combined))
    fails  = sum(int(x) for x in re.findall(r"# FAIL:\s*(\d+)", combined))
    if passes or fails:
        line = f"PASS={passes} FAIL={fails}"
        if fails == 0:
            return "pass", line
        if passes > 0:
            return "partial", line
        return "fail", line

    m = re.search(r"(\d+) (?:test[s]? passed|passed)", combined, re.I)
    if m and returncode == 0:
        return "pass", m.group(0)

    # No parseable pass/fail evidence at all. A clean exit here just means
    # the test runner found nothing to run (e.g. no CTestTestfile.cmake
    # registered) — NOT that anything passed. Report this distinctly so
    # callers can fall back to the build result instead of silently
    # treating "ran nothing" as "passed".
    if returncode == 0:
        return "no_tests", "exit 0, no parseable test results"
    return "fail", f"exit {returncode}"


def run_build(repo_path: Path, build_timeout: int) -> tuple[bool, str, str]:
    """Incremental rebuild after patching. Returns (ok, summary, error_output)."""
    cmake_build = repo_path / "_cmake_build"

    if cmake_build.exists():
        r = _run([CMAKE, "--build", str(cmake_build), "--parallel", "4"],
                 cwd=repo_path, timeout=build_timeout)
        if r is None:
            return False, "cmake build timeout", ""
        err = _trim_output(r.stdout + r.stderr) if r.returncode != 0 else ""
        return r.returncode == 0, f"cmake rc={r.returncode}", err

    if (repo_path / "Makefile").exists():
        r = _run(["make", "-j4", "-k", "--keep-going"], cwd=repo_path, timeout=build_timeout)
        if r is None:
            return False, "make timeout", ""
        err = _trim_output(r.stdout + r.stderr) if r.returncode != 0 else ""
        return r.returncode == 0, f"make rc={r.returncode}", err

    return False, "no build system", ""


def run_testsuite(repo_path: Path, test_timeout: int) -> dict:
    cmake_build = repo_path / "_cmake_build"
    ctest = Path(CMAKE).parent / "ctest"

    if cmake_build.exists() and ctest.exists():
        r = _run([str(ctest), "--test-dir", str(cmake_build),
                  "--output-on-failure", "-j4",
                  "--timeout", str(test_timeout // 2)],
                 cwd=repo_path, timeout=test_timeout)
        if r is not None:
            combined = r.stdout + r.stderr
            verdict, summary = _parse_test_summary(combined, r.returncode)
            err = "" if verdict == "pass" else _trim_output(combined)
            return {"suite_cmd": "ctest", "returncode": r.returncode,
                    "verdict": verdict, "summary": summary, "error_output": err}
        return {"suite_cmd": "ctest", "returncode": -1,
                "verdict": "fail", "summary": "timeout", "error_output": ""}

    if (repo_path / "Makefile").exists():
        mf_text = (repo_path / "Makefile").read_text(errors="replace")
        for target in ("check", "test", "tests"):
            if not re.search(rf"^{target}\s*:", mf_text, re.MULTILINE):
                continue
            r = _run(["make", target, "-k"], cwd=repo_path, timeout=test_timeout)
            if r is None:
                return {"suite_cmd": f"make {target}", "returncode": -1,
                        "verdict": "fail", "summary": "timeout", "error_output": ""}
            combined = r.stdout + r.stderr
            verdict, summary = _parse_test_summary(combined, r.returncode)
            err = "" if verdict == "pass" else _trim_output(combined)
            return {"suite_cmd": f"make {target}", "returncode": r.returncode,
                    "verdict": verdict, "summary": summary, "error_output": err}

    return {"suite_cmd": None, "returncode": None,
            "verdict": "none", "summary": "no test target found", "error_output": ""}


# ---------------------------------------------------------------------------
# Per-sample processing (repo already cloned and built)
# ---------------------------------------------------------------------------

def process_one(pid: str, meta: dict, repo_path: Path,
                samples_dir: Path, output_dir: Path,
                build_timeout: int, test_timeout: int, force: bool) -> dict:
    out_d       = output_dir / pid
    result_path = out_d / "attacker_result.json"

    if not force and result_path.exists():
        return {"pid": pid, "status": "skip"}

    attacker_path = out_d / "attacker_output.cc"
    if not attacker_path.exists():
        return {"pid": pid, "status": "skip_no_output"}

    func_name = meta.get("func_name") or meta.get("function", "")
    file_path = meta.get("file_path") or meta.get("file", "")
    src_file  = repo_path / file_path

    out_d.mkdir(parents=True, exist_ok=True)

    if not src_file.exists():
        result = {"pid": pid, "status": "fail",
                  "error": f"source file missing in clone: {file_path}"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    attacker_src = attacker_path.read_text(errors="replace")
    body = extract_body(func_name, attacker_src)
    if body is None:
        result = {"pid": pid, "status": "fail",
                  "error": f"could not extract {func_name} from attacker_output.cc"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    original_src = src_file.read_text(errors="replace")
    patched = splice_body(func_name, original_src, body)
    if patched is None:
        result = {"pid": pid, "status": "fail",
                  "error": f"could not find {func_name} in repo source {file_path}"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    src_file.write_text(patched, errors="replace")
    try:
        build_ok, build_summary, build_error = run_build(repo_path, build_timeout)
        # Always attempt the test suite, even after a build failure — an
        # unrelated target can fail while the code we actually patched still
        # built and is exercised by tests elsewhere ("don't give up" case).
        # Only fall back to the build result when the test suite gives us
        # no real evidence either way (no tests registered / no test target
        # found) — a failed build with nothing to redeem it is excluded, but
        # a failed build whose tests genuinely ran and passed is trusted.
        suite = run_testsuite(repo_path, test_timeout)
        if suite["verdict"] in ("no_tests", "none"):
            if build_ok:
                suite["verdict"] = "pass"
            else:
                suite["verdict"] = "fail"
                suite["summary"] = f"build failed, no tests to fall back on ({build_summary})"
                suite["error_output"] = build_error

        result = {
            "pid":           pid,
            "status":        "ok",
            "func_name":     func_name,
            "file_path":     file_path,
            "build_ok":      build_ok,
            "build_summary": build_summary,
            "suite_cmd":     suite.get("suite_cmd"),
            "returncode":    suite.get("returncode"),
            "verdict":       suite.get("verdict"),
            "summary":       suite.get("summary"),
            "error_output":  suite.get("error_output", ""),
        }
    finally:
        # Restore via git — clean and guaranteed correct
        subprocess.run(["git", "checkout", "--", file_path],
                       cwd=str(repo_path), capture_output=True)

    result_path.write_text(json.dumps(result, indent=2))
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("jsonl")
    ap.add_argument("ids",             nargs="*", help="Pilot IDs to process (default: all)")
    ap.add_argument("--ids-file",      help="File with one pilot ID per line")
    ap.add_argument("--samples-dir",   default=str(DEFAULT_SAMPLES),
                    help="Directory with pipeline inputs and sentinels")
    ap.add_argument("--output-dir",    default=None,
                    help="Directory with attacker_output.cc / results (default: --samples-dir)")
    ap.add_argument("--clone-dir",     default=str(DEFAULT_CLONE),
                    help="Scratch directory for fresh repo clones")
    ap.add_argument("--build-timeout", type=int, default=BUILD_TIMEOUT)
    ap.add_argument("--test-timeout",  type=int, default=TEST_TIMEOUT)
    ap.add_argument("--force",         action="store_true")
    ap.add_argument("--keep-clones",   action="store_true",
                    help="Don't delete clones after processing (useful for debugging)")
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    output_dir  = Path(args.output_dir) if args.output_dir else samples_dir
    clone_dir   = Path(args.clone_dir)
    clone_dir.mkdir(parents=True, exist_ok=True)

    rows = {json.loads(l)["pilot_id"]: json.loads(l)
            for l in Path(args.jsonl).read_text().splitlines() if l.strip()}

    if args.ids_file:
        pids = [l.strip() for l in Path(args.ids_file).read_text().splitlines() if l.strip()]
        pids = [p for p in pids if p in rows]
    elif args.ids:
        pids = [p for p in args.ids if p in rows]
    else:
        pids = list(rows.keys())

    # Filter: needs attacker_output.cc and testsuite_pass sentinel
    viable = [p for p in pids
              if (output_dir / p / "attacker_output.cc").exists()
              and (samples_dir / p / "repo_testsuite_pass").exists()]

    print(f"Patch-and-test for {len(viable)} samples")
    print(f"  inputs  → {samples_dir}/")
    print(f"  outputs → {output_dir}/")
    print(f"  clones  → {clone_dir}/\n")

    # Group by repo
    by_repo: dict[str, list[str]] = {}
    for pid in viable:
        slug = repo_slug(rows[pid].get("repo_url", ""))
        by_repo.setdefault(slug, []).append(pid)

    counts: dict[str, int] = {}
    all_results = []

    for slug, repo_pids in sorted(by_repo.items()):
        print(f"\n{'='*55}\n{slug}  ({len(repo_pids)} samples)")

        # Use any sample's metadata for repo_url + commit_hash
        sample_meta = rows[repo_pids[0]]
        repo_url    = sample_meta.get("repo_url", "")
        commit_hash = sample_meta.get("commit_hash", "")

        # Clone fresh + configure + full build
        print(f"  Cloning {repo_url} @ {commit_hash[:8]}...")
        repo_path, build_summary = clone_and_build(
            repo_url, commit_hash, clone_dir, args.build_timeout)

        if repo_path is None:
            print(f"  CLONE/BUILD FAILED: {build_summary}")
            for pid in repo_pids:
                result = {"pid": pid, "status": "fail", "error": f"clone/build failed: {build_summary}"}
                out_d = output_dir / pid
                out_d.mkdir(parents=True, exist_ok=True)
                (out_d / "attacker_result.json").write_text(json.dumps(result, indent=2))
                all_results.append(result)
                counts["fail"] = counts.get("fail", 0) + 1
            continue

        print(f"  Build: {build_summary}")

        for pid in repo_pids:
            result = process_one(
                pid, rows[pid], repo_path, samples_dir, output_dir,
                args.build_timeout, args.test_timeout, args.force,
            )
            status  = result.get("status", "?")
            verdict = result.get("verdict", "")
            counts[status] = counts.get(status, 0) + 1
            all_results.append(result)
            label = verdict if status == "ok" else status
            print(f"  {pid}: {label}  —  {result.get('summary', result.get('error', ''))}")

        # Clean up clone
        if not args.keep_clones:
            shutil.rmtree(repo_path, ignore_errors=True)
            print(f"  Deleted clone.")

    out_path = output_dir / "attacker_results.json"
    out_path.write_text(json.dumps(all_results, indent=2))
    print(f"\nResults → {out_path}")
    print(f"\nDone: {counts}")


if __name__ == "__main__":
    main()
