#!/usr/bin/env python3
"""
Patch attacker_output.cc into the original repo, recompile, run tests.

For each sample with attacker_output.cc:
  1. Extract the target function body from attacker_output.cc
  2. Splice it into /tmp/cve_repos_fix/<slug>/<file_path>
  3. Recompile (incremental build)
  4. Run test suite
  5. Save result as attacker_result.json
  6. Restore original source file

Repos are processed serially (one sample at a time per repo) to avoid
concurrent writes to the same source file.

Usage:
  python3 repo_cve_dataset_mining_new/patch_and_test.py \\
      repo_cve_dataset_mining_new/f3_nolimit_dedup_func.jsonl \\
      [NPD-CVE-0001 ...] \\
      [--samples-dir repo_cve_dataset_mining_new/samples_cve_fix] \\
      [--clone-dir /tmp/cve_repos_fix] \\
      [--build-timeout 300] [--test-timeout 300] [--force]
"""

import json
import re
import subprocess
from pathlib import Path

CMAKE         = "/usr/bin/cmake"
HERE          = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve_fix"
DEFAULT_CLONE   = Path("/tmp/cve_repos_fix")

BUILD_TIMEOUT = 300
TEST_TIMEOUT  = 300


# ---------------------------------------------------------------------------
# Helpers shared with generate_task_only.py
# ---------------------------------------------------------------------------

def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


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
    """Return (sig_char_start, open_brace_pos, close_brace_pos) or None.

    sig_char_start is the character index of the line containing the
    function signature.  open/close are absolute offsets into src.
    Skips forward declarations (semicolon before opening brace).
    """
    fn_re = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    lines = src.splitlines(keepends=True)
    char_offset = 0
    for i, line in enumerate(lines):
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
                continue  # forward declaration
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
    """Return the {body} of func_name (including braces), or None."""
    loc = _find_func(func_name, src)
    if loc is None:
        return None
    _, open_abs, close_abs = loc
    return src[open_abs:close_abs]


def splice_body(func_name: str, repo_src: str, new_body: str) -> str | None:
    """Replace func_name's {body} in repo_src with new_body. Return patched src or None."""
    loc = _find_func(func_name, repo_src)
    if loc is None:
        return None
    _, open_abs, close_abs = loc
    return repo_src[:open_abs] + new_body + repo_src[close_abs:]


# ---------------------------------------------------------------------------
# Build + test
# ---------------------------------------------------------------------------

def _trim_output(s: str) -> str:
    """Keep first 20K + last 20K chars so both early errors and final summary are visible."""
    if len(s) <= 40000:
        return s
    return s[:20000] + "\n\n... (truncated) ...\n\n" + s[-20000:]


def run_incremental_build(repo_path: Path, build_timeout: int) -> tuple[bool, str, str]:
    """Returns (ok, summary, error_output)."""
    cmake_build = repo_path / "_cmake_build"

    def run(cmd, cwd=None):
        try:
            return subprocess.run(
                cmd, cwd=str(cwd or repo_path),
                capture_output=True, text=True, timeout=build_timeout,
            )
        except subprocess.TimeoutExpired:
            return None

    if cmake_build.exists():
        r = run([CMAKE, "--build", str(cmake_build), "--parallel", "4"])
        if r is None:
            return False, "cmake build timeout", ""
        ok = r.returncode == 0
        err = "" if ok else _trim_output(r.stdout + r.stderr)
        return ok, f"cmake rc={r.returncode}", err

    if (repo_path / "Makefile").exists():
        r = run(["make", "-j4", "-k"])
        if r is None:
            return False, "make timeout", ""
        ok = r.returncode == 0
        err = "" if ok else _trim_output(r.stdout + r.stderr)
        return ok, f"make rc={r.returncode}", err

    return False, "no build system", ""


def _parse_test_summary(output: str, returncode: int) -> tuple[str, str]:
    combined = output or ""

    m = re.search(r"(\d+)% tests passed.*?out of (\d+)", combined)
    if m:
        pct = int(m.group(1))
        line = m.group(0)
        if pct == 100:
            return "pass", line
        if pct >= 50:
            return "partial", line
        return "fail", line

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

    if returncode == 0:
        return "pass", "exit 0"
    return "fail", f"exit {returncode}"


def run_testsuite(repo_path: Path, test_timeout: int) -> dict:
    cmake_build = repo_path / "_cmake_build"

    def run(cmd, cwd=None):
        try:
            return subprocess.run(
                cmd, cwd=str(cwd or repo_path),
                capture_output=True, text=True, timeout=test_timeout,
            )
        except subprocess.TimeoutExpired:
            return None

    ctest = Path(CMAKE).parent / "ctest"
    if cmake_build.exists() and ctest.exists():
        r = run([str(ctest), "--test-dir", str(cmake_build),
                 "--output-on-failure", "-j4",
                 "--timeout", str(test_timeout // 2)])
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
            r = run(["make", target, "-k"])
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
# Per-sample processing
# ---------------------------------------------------------------------------

def process_one(pid: str, meta: dict, samples_dir: Path, output_dir: Path,
                clone_dir: Path, build_timeout: int, test_timeout: int, force: bool) -> dict:
    sample_dir  = samples_dir / pid   # sentinels / metadata live here
    out_d       = output_dir / pid    # attacker_output.cc and results live here
    result_path = out_d / "attacker_result.json"

    if not force and result_path.exists():
        return {"pid": pid, "status": "skip"}

    attacker_path = out_d / "attacker_output.cc"
    if not attacker_path.exists():
        return {"pid": pid, "status": "skip_no_output"}

    func_name = meta.get("func_name") or meta.get("function", "")
    file_path = meta.get("file_path") or meta.get("file", "")
    repo_url  = meta.get("repo_url", "")
    slug      = repo_slug(repo_url)
    repo_path = clone_dir / slug
    src_file  = repo_path / file_path

    out_d.mkdir(parents=True, exist_ok=True)

    if not repo_path.exists():
        result = {"pid": pid, "status": "fail", "error": f"repo clone missing: {repo_path}"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    if not src_file.exists():
        result = {"pid": pid, "status": "fail",
                  "error": f"source file missing in clone: {file_path}"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    # Extract the attacker's function body
    attacker_src = attacker_path.read_text()
    body = extract_body(func_name, attacker_src)
    if body is None:
        result = {"pid": pid, "status": "fail",
                  "error": f"could not extract {func_name} from attacker_output.cc"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    # Write .bak before touching the source — survives hard kills
    original_src = src_file.read_text(errors="replace")
    bak_file = src_file.with_suffix(src_file.suffix + ".bak")
    if bak_file.exists():
        # Leftover from a previous crash — restore it before proceeding
        print(f"  {pid}: WARNING stale .bak found, restoring before patch")
        src_file.write_text(bak_file.read_text(errors="replace"), errors="replace")
        original_src = src_file.read_text(errors="replace")
    bak_file.write_text(original_src, errors="replace")

    patched = splice_body(func_name, original_src, body)
    if patched is None:
        bak_file.unlink(missing_ok=True)
        result = {"pid": pid, "status": "fail",
                  "error": f"could not find {func_name} in repo source {file_path}"}
        result_path.write_text(json.dumps(result, indent=2))
        return result

    src_file.write_text(patched, errors="replace")
    try:
        build_ok, build_summary, build_error = run_incremental_build(repo_path, build_timeout)
        if not build_ok:
            suite = {"suite_cmd": None, "returncode": None,
                     "verdict": "fail", "summary": "build failed", "error_output": build_error}
        else:
            suite = run_testsuite(repo_path, test_timeout)

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
        src_file.write_text(original_src, errors="replace")
        bak_file.unlink(missing_ok=True)

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
                    help="Directory with attacker_output.cc to patch (default: --samples-dir)")
    ap.add_argument("--clone-dir",     default=str(DEFAULT_CLONE))
    ap.add_argument("--build-timeout", type=int, default=BUILD_TIMEOUT)
    ap.add_argument("--test-timeout",  type=int, default=TEST_TIMEOUT)
    ap.add_argument("--force",         action="store_true")
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    output_dir  = Path(args.output_dir) if args.output_dir else samples_dir
    clone_dir   = Path(args.clone_dir)

    rows = {json.loads(l)["pilot_id"]: json.loads(l)
            for l in Path(args.jsonl).read_text().splitlines() if l.strip()}

    if args.ids_file:
        pids = [l.strip() for l in Path(args.ids_file).read_text().splitlines() if l.strip()]
        pids = [p for p in pids if p in rows]
    elif args.ids:
        pids = [p for p in args.ids if p in rows]
    else:
        pids = list(rows.keys())

    # Filter: needs attacker_output.cc in output_dir and testsuite_pass sentinel in samples_dir
    viable = []
    for pid in pids:
        if not (output_dir / pid / "attacker_output.cc").exists():
            continue
        if not (samples_dir / pid / "repo_testsuite_pass").exists():
            continue
        viable.append(pid)

    print(f"Patch-and-test for {len(viable)} samples\n  inputs  → {samples_dir}/\n  outputs → {output_dir}/\n")

    # Group by repo so we process one sample per repo at a time (serial within repo)
    by_repo: dict[str, list[str]] = {}
    for pid in viable:
        slug = repo_slug(rows[pid].get("repo_url", ""))
        by_repo.setdefault(slug, []).append(pid)

    counts: dict[str, int] = {}
    all_results = []

    for slug, repo_pids in sorted(by_repo.items()):
        print(f"\n{'='*55}\n{slug}  ({len(repo_pids)} samples)")
        for pid in repo_pids:
            meta = rows[pid]
            result = process_one(
                pid, meta, samples_dir, output_dir, clone_dir,
                args.build_timeout, args.test_timeout, args.force,
            )
            status  = result.get("status", "?")
            verdict = result.get("verdict", "")
            counts[status] = counts.get(status, 0) + 1
            all_results.append(result)
            label = verdict if status == "ok" else status
            print(f"  {pid}: {label}  —  {result.get('summary', result.get('error', ''))}")

    out_path = output_dir / "attacker_results.json"
    out_path.write_text(json.dumps(all_results, indent=2))
    print(f"\nResults → {out_path}")
    print(f"\nDone: {counts}")


if __name__ == "__main__":
    main()
