#!/usr/bin/env python3
"""
build_with_repo_headers.py — Compile CVE samples against their real repo headers.

Instead of the LLM portability pass (which makes code standalone), this script:
  1. Groups samples by repo (102 unique repos across 835 samples).
  2. Shallow-clones each repo (headers only, no full build needed).
  3. Tries compiling context.cc [+ auxiliary.cc] + tests.cc with heuristic -I paths.
  4. Marks tests_validated for samples that compile, run, and discriminate the stub.
  5. Reuses existing task.md as-is. tests.cc is retried before any regen.

No LLM needed for include-flag discovery — standard C/C++ projects almost always
put headers in include/, src/, or the repo root.

Usage:
  python3 repo_cve_dataset_mining/build_with_repo_headers.py \\
      repo_cve_dataset_mining/f3_nolimit_dedup_func.jsonl \\
      --samples-dir repo_cve_dataset_mining/samples_ts_final \\
      --clone-dir /tmp/cve_repos \\
      [--skip-repos torvalds/linux xen-project/xen qemu/qemu tensorflow/tensorflow] \\
      [--workers 4]

Requires: git, gcc/g++
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent

DEFAULT_SKIP = {
    "torvalds/linux",
    "xen-project/xen",
    "qemu/qemu",
    "tensorflow/tensorflow",
}

# Heuristic include subdirs to try inside a cloned repo
HEURISTIC_DIRS = [".", "include", "src", "lib", "source", "headers"]


# ---------------------------------------------------------------------------
# Repo cloning
# ---------------------------------------------------------------------------

def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


def clone_repo(url: str, clone_dir: Path, commit: str) -> Path | None:
    dest = clone_dir / repo_slug(url)
    if (dest / ".git").exists():
        return dest

    print(f"  Cloning {url} …")
    r = subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dest)],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        first = r.stderr.splitlines()[0][:120] if r.stderr else "(no output)"
        print(f"    FAIL: {first}")
        shutil.rmtree(dest, ignore_errors=True)
        return None

    # Sparse checkout: only headers and top-level files (no source blobs)
    subprocess.run(["git", "-C", str(dest), "sparse-checkout", "init", "--cone"],
                   capture_output=True)
    subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set",
                    "include", "src", "lib", "source", "headers", "."],
                   capture_output=True)

    # Try buggy commit first (parent of fix), fall back to fix commit
    for ref in [commit + "~1", commit, "HEAD"]:
        r = subprocess.run(["git", "-C", str(dest), "checkout", ref],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            print(f"    OK at {ref}")
            return dest

    print(f"    FAIL: could not checkout any ref")
    shutil.rmtree(dest, ignore_errors=True)
    return None


def get_include_flags(repo_path: Path) -> list[str]:
    """Return heuristic -I flags for a cloned repo."""
    flags = []
    for d in HEURISTIC_DIRS:
        p = repo_path / d
        if p.is_dir():
            flags.append(f"-I{p}")
    # Also add any immediate subdirectory named after the repo
    slug = repo_path.name.split("__")[-1]  # e.g. "jasper" from "jasper-software__jasper"
    p = repo_path / "include" / slug
    if p.is_dir():
        flags.append(f"-I{p}")
    return flags


# ---------------------------------------------------------------------------
# Compile + validate
# ---------------------------------------------------------------------------

def try_compile(sample_dir: Path, tests_src: str, lang: str,
                extra_flags: list[str], pid: str) -> str | None:
    """Compile context.cc [+ auxiliary.cc] + tests_src. Returns None on success."""
    context  = sample_dir / "context.cc"
    aux      = sample_dir / "auxiliary.cc"
    compiler = "g++" if lang == "cpp" else "gcc"
    flags    = "-std=c++17" if lang == "cpp" else "-std=c11"
    suffix   = ".cc" if lang == "cpp" else ".c"
    harness  = sample_dir / "test_harness_repo"

    combined = context.read_text()
    if aux.exists():
        combined += "\n" + aux.read_text()
    combined += "\n" + tests_src

    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as f:
        f.write(combined); tmp = f.name

    try:
        cmd = f"{compiler} {flags} -w {' '.join(extra_flags)} {tmp} -o {harness} -lm"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return "\n".join(r.stderr.splitlines()[:15])
        r2 = subprocess.run([str(harness)], capture_output=True, text=True, timeout=30)
        harness.unlink(missing_ok=True)
        if r2.returncode != 0:
            return r2.stdout[:400] + r2.stderr[:200]
        return None
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(str(harness)).unlink(missing_ok=True)


def stub_discriminates(sample_dir: Path, tests_src: str, lang: str,
                       extra_flags: list[str]) -> bool:
    """Return True if starter.cc (stub) fails the tests — tests are discriminating."""
    starter = sample_dir / "starter.cc"
    if not starter.exists():
        return True
    aux      = sample_dir / "auxiliary.cc"
    compiler = "g++" if lang == "cpp" else "gcc"
    flags    = "-std=c++17" if lang == "cpp" else "-std=c11"
    suffix   = ".cc" if lang == "cpp" else ".c"
    harness  = sample_dir / "test_harness_stub"

    combined = starter.read_text()
    if aux.exists():
        combined += "\n" + aux.read_text()
    combined += "\n" + tests_src

    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as f:
        f.write(combined); tmp = f.name
    try:
        r = subprocess.run(
            f"{compiler} {flags} -w {' '.join(extra_flags)} {tmp} -o {harness} -lm",
            shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return True  # stub fails to compile → discriminates
        r2 = subprocess.run([str(harness)], capture_output=True, text=True, timeout=30)
        harness.unlink(missing_ok=True)
        return r2.returncode != 0
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(str(harness)).unlink(missing_ok=True)


def context_compiles(sample_dir: Path, lang: str, extra_flags: list[str]) -> bool:
    """Check if context.cc [+ auxiliary.cc] compiles on its own."""
    context  = sample_dir / "context.cc"
    aux      = sample_dir / "auxiliary.cc"
    compiler = "g++" if lang == "cpp" else "gcc"
    flags    = "-std=c++17" if lang == "cpp" else "-std=c11"
    suffix   = ".cc" if lang == "cpp" else ".c"

    src = context.read_text()
    if aux.exists():
        src += "\n" + aux.read_text()

    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as f:
        f.write(src); tmp = f.name
    try:
        r = subprocess.run(
            f"{compiler} {flags} -w {' '.join(extra_flags)} {tmp} -o /dev/null -lm",
            shell=True, capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    finally:
        Path(tmp).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Process one sample
# ---------------------------------------------------------------------------

def process_sample(pid: str, sample_dir: Path, lang: str,
                   include_flags: list[str]) -> dict:
    """Returns a result dict with 'outcome' and optional 'error'."""
    def result(outcome: str, error: str = "") -> dict:
        return {"pid": pid, "outcome": outcome, "error": error,
                "include_flags": include_flags}

    if not sample_dir.exists():
        return result("skip")
    if not (sample_dir / "context.cc").exists():
        return result("skip")
    if not (sample_dir / "tests.cc").exists():
        return result("skip")
    if (sample_dir / "tests_validated").exists():
        return result("already_validated")

    tests_src = (sample_dir / "tests.cc").read_text()
    err = try_compile(sample_dir, tests_src, lang, include_flags, pid)

    if err is None:
        if not stub_discriminates(sample_dir, tests_src, lang, include_flags):
            print(f"  {pid}: tests too weak (stub passes)")
            return result("tests_fail", "stub passes all tests")
        (sample_dir / "tests_validated").touch()
        (sample_dir / "tests_unvalidated").unlink(missing_ok=True)
        print(f"  {pid}: VALIDATED ✓")
        return result("validated")

    first_err = err.splitlines()[0][:120] if err else "(unknown)"
    if context_compiles(sample_dir, lang, include_flags):
        print(f"  {pid}: context OK, tests fail — {first_err}")
        return result("tests_fail", first_err)
    else:
        print(f"  {pid}: context fail — {first_err}")
        return result("context_fail", first_err)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--samples-dir", default=str(HERE / "samples_ts_final"))
    ap.add_argument("--clone-dir",   default="/tmp/cve_repos")
    ap.add_argument("--skip-repos",  nargs="*", default=list(DEFAULT_SKIP))
    ap.add_argument("--workers",     type=int, default=1)
    ap.add_argument("--dry-run",     action="store_true",
                    help="Clone and show include flags, but skip compilation")
    ap.add_argument("--out", default=None,
                    help="Write JSON results summary (default: <samples-dir>/repo_headers_results.json)")
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    clone_dir   = Path(args.clone_dir)
    clone_dir.mkdir(parents=True, exist_ok=True)
    skip_repos  = set(args.skip_repos)

    rows = [json.loads(l) for l in Path(args.jsonl).read_text().splitlines() if l.strip()]

    # Group by repo
    by_repo: dict[str, list[dict]] = {}
    for row in rows:
        url  = row.get("repo_url", "")
        slug = url.replace("https://github.com/", "")
        if url:
            by_repo.setdefault(slug, []).append(row)

    print(f"Repos: {len(by_repo)}  |  Skipping: {len(skip_repos)}")
    print(f"Samples dir: {samples_dir}")
    print(f"Clone dir:   {clone_dir}\n")

    out_path = Path(args.out) if args.out else samples_dir / "repo_headers_results.json"
    counts   = {"validated": 0, "already_validated": 0,
                "context_fail": 0, "tests_fail": 0, "skip": 0, "repo_skip": 0}
    all_results: list[dict] = []

    for slug, repo_rows in sorted(by_repo.items(), key=lambda x: -len(x[1])):
        if slug in skip_repos:
            print(f"[SKIP] {slug} ({len(repo_rows)} samples)")
            counts["repo_skip"] += len(repo_rows)
            for row in repo_rows:
                all_results.append({"pid": row["pilot_id"], "outcome": "repo_skip",
                                    "repo": slug, "error": "", "include_flags": []})
            continue

        commits = [r.get("commit_hash", "") for r in repo_rows if r.get("commit_hash")]
        commit  = commits[0] if commits else "HEAD"
        url     = f"https://github.com/{slug}"

        print(f"\n{'='*60}")
        print(f"{slug}  ({len(repo_rows)} samples)")

        repo_path = clone_repo(url, clone_dir, commit)
        if repo_path is None:
            counts["repo_skip"] += len(repo_rows)
            for row in repo_rows:
                all_results.append({"pid": row["pilot_id"], "outcome": "repo_skip",
                                    "repo": slug, "error": "clone failed", "include_flags": []})
            continue

        include_flags = get_include_flags(repo_path)
        print(f"  include flags: {include_flags}")

        if args.dry_run:
            print(f"  [dry-run] skipping compilation")
            continue

        for row in repo_rows:
            pid  = row["pilot_id"]
            lang = row.get("lang") or (
                "cpp" if Path(row.get("file_path", row.get("file", ""))).suffix.lower()
                         in (".cpp", ".cc", ".cxx", ".hpp", ".hh") else "c")
            r = process_sample(pid, samples_dir / pid, lang, include_flags)
            r["repo"] = slug
            all_results.append(r)
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

    if not args.dry_run:
        out_path.write_text(json.dumps(all_results, indent=2))
        print(f"\nResults saved → {out_path}")

    print(f"\n{'='*60}")
    print(f"Summary:")
    for k, v in counts.items():
        print(f"  {k:20s}: {v}")
    print(f"\n  total validated: {counts['validated'] + counts['already_validated']}")
    print(f"\nNext step for context_fail repos: run with --llm-fix (not yet implemented)")
    print(f"Next step for tests_fail samples:  regenerate tests.cc via generate_task_cve.py --force")


if __name__ == "__main__":
    main()
