"""
CodeQL UseAfterFree.ql catch-rate on the 70 judge-confirmed CVE UAF samples.
UAF counterpart of sa_codeql.py.

Uses a REAL traced build (codeql's default C/C++ tracing, --command=<build>),
not --build-mode=none. --build-mode=none was tried first and found to be
unreliable for these repos: inspecting the extractor diagnostics for a live
DB (facebook/hermes) showed 45% of files (252/559) failed extraction because
the no-build heuristic can't resolve project-specific include paths/macros
without a real compile. CodeQL's own docs flag build-mode=none as unreliable
for compiled languages.

Each repo clone under /tmp/cve_repos_uaf was already configured + fully
built once by check_repo_testsuite.py (Makefile/_cmake_build + .o files
already present). So per-sample here we only need a fast INCREMENTAL
rebuild traced by `codeql database create --command=...` — patch the target
file, bump its mtime into the future (so make/cmake reliably sees it as
changed even under same-second timestamp resolution), and let the existing
build system recompile just that translation unit under the CodeQL tracer.

Per-slug: patches target file with vulnerable version -> traced incremental
build -> runs query -> restores. Slugs sharing the same repo run SERIALLY
to avoid concurrent file/build conflicts.

Manifest (uaf_clone_manifest.json) is derived directly from
cvebench/f3_uaf_ids.jsonl + the already-populated /tmp/cve_repos_uaf clone
dir from check_repo_testsuite.py — no separate cloning step needed.

Usage:
    python result_analysis/static_analyzer/sa_codeql_uaf.py [--resume]

Output:
    result_analysis/static_analyzer/sa_codeql_uaf.json
"""

import argparse
import json
import os
import subprocess
import shutil
import time
from collections import defaultdict
from pathlib import Path

BENCH_ROOT  = Path("/mnt/ssd/aryawu/redteaming_code_auditors/benchmark/cvebench_full_uaf/baseline")
MANIFEST    = Path(__file__).parent / "uaf_clone_manifest.json"
OUT_PATH    = Path(__file__).parent / "sa_codeql_uaf.json"
DB_ROOT     = Path("/tmp/cve_sa_codeql_uaf_dbs")

CODEQL = "/mnt/ssd/aryawu/codeql-home/codeql/codeql"
QUERY  = "/mnt/ssd/aryawu/.codeql/packages/codeql/cpp-queries/1.6.3/Critical/UseAfterFree.ql"
CMAKE  = "/usr/bin/cmake"

DB_TIMEOUT = 900


def load_samples():
    manifest = json.loads(MANIFEST.read_text())
    samples = []
    for repo_dir in sorted(BENCH_ROOT.iterdir()):
        for f in sorted(repo_dir.iterdir()):
            if f.name.endswith("_CLEAN.json"):
                item = json.loads(f.read_text())[0]
                slug = item["slug"]
                m = manifest.get(slug, {})
                item["clone_dir"]      = m.get("clone_dir")
                item["vuln_file_path"] = m.get("file")
                samples.append(item)
    return samples


WRAPPER_DIR = DB_ROOT / "_build_wrappers"


def get_build_command(repo_path: Path) -> str | None:
    """Path to a wrapper script that runs an incremental build for an
    already-configured, already-built repo. Wrapped in its own script (not
    passed inline via --command) because CodeQL's --command value is
    whitespace-tokenized rather than shell-parsed, so quoting a compound
    command (e.g. `sh -c '...; exit 0'`) inline breaks. The trailing
    `exit 0` matters: these large legacy C codebases routinely have a few
    files that don't compile cleanly (pre-existing, unrelated to whichever
    sample we're currently patching — confirmed on ghostpdl, where make
    fails on 2 unrelated files every run) and CodeQL refuses to finalize
    the database at all if the traced command exits non-zero. Forcing
    exit 0 lets it finalize with whatever it managed to extract — and the
    C++ extractor still parses files whose *compile* failed downstream
    (verified: gdevxps.c/ttinterp.c both fail to `make` here but both still
    show up as extracted artifacts in the resulting database)."""
    cmake_build = repo_path / "_cmake_build"
    if cmake_build.exists():
        build_cmd = f'"{CMAKE}" --build "{cmake_build}" --parallel 4'
    elif (repo_path / "Makefile").exists():
        build_cmd = "make -j4 -k --keep-going"
    else:
        return None

    WRAPPER_DIR.mkdir(parents=True, exist_ok=True)
    wrapper = WRAPPER_DIR / f"{repo_path.name}.sh"
    wrapper.write_text(f"#!/bin/bash\n{build_cmd}\nexit 0\n")
    wrapper.chmod(0o755)
    return f"bash {wrapper}"


def build_db(repo_path: Path, db_path: Path, command: str) -> tuple[bool, str]:
    """Build CodeQL DB by tracing a real (incremental) build command."""
    r = subprocess.run(
        [CODEQL, "database", "create", str(db_path),
         "--language=cpp",
         "--source-root", str(repo_path),
         f"--command={command}",
         "--overwrite"],
        capture_output=True, text=True, timeout=DB_TIMEOUT
    )
    if r.returncode != 0:
        return False, r.stderr[-300:]
    return True, ""


def run_query(db_path: Path, sarif_path: Path) -> list[dict]:
    """Run UseAfterFree.ql, return list of {uri, line} hits."""
    r = subprocess.run(
        [CODEQL, "database", "analyze", str(db_path),
         QUERY,
         "--format=sarifv2.1.0",
         f"--output={sarif_path}",
         "--rerun"],
        capture_output=True, text=True, timeout=600
    )
    if not sarif_path.exists():
        return []
    sarif = json.loads(sarif_path.read_text())
    hits = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                pl   = loc.get("physicalLocation", {})
                uri  = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine", 0)
                hits.append({"uri": uri, "line": line})
    return hits


def run_codeql_on_slug(sample: dict, build_command: str) -> dict:
    slug      = sample["slug"]
    fn        = sample["function_name"]
    src       = sample["primary_file"]
    clone_dir = sample["clone_dir"]
    vuln_fp   = sample["vuln_file_path"]

    repo_path   = Path(clone_dir)
    target_file = repo_path / vuln_fp
    if not target_file.exists():
        return {"slug": slug, "hit_in_target_file": None,
                "error": f"file not found: {vuln_fp}"}

    db_path    = DB_ROOT / f"{slug}_db"
    sarif_path = DB_ROOT / f"{slug}.sarif"
    DB_ROOT.mkdir(parents=True, exist_ok=True)

    original = target_file.read_text(errors="replace")
    try:
        target_file.write_text(src)
        # Bump mtime into the future so make/cmake reliably treats the file
        # as changed even if the write lands in the same second as the
        # previous build (common under fast incremental rebuilds).
        future = time.time() + 5
        os.utime(target_file, (future, future))

        ok, err = build_db(repo_path, db_path, build_command)
        if not ok:
            return {"slug": slug, "hit_in_target_file": None,
                    "error": f"db_build_failed: {err}"}

        hits = run_query(db_path, sarif_path)

        target_fname = Path(vuln_fp).name
        in_file      = [h for h in hits if target_fname in h["uri"]]
        return {
            "slug":               slug,
            "function_name":      fn,
            "hit_in_target_file": bool(in_file),
            "hit_anywhere":       bool(hits),
            "total_hits":         len(hits),
            "hits_in_file":       in_file[:10],
        }
    except subprocess.TimeoutExpired:
        return {"slug": slug, "hit_in_target_file": None, "error": "timeout"}
    except Exception as e:
        return {"slug": slug, "hit_in_target_file": None, "error": str(e)}
    finally:
        target_file.write_text(original)
        shutil.rmtree(db_path, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true",
                        help="Skip slugs already in output file")
    args = parser.parse_args()

    samples = load_samples()

    results: dict[str, dict] = {}
    if OUT_PATH.exists():
        for r in json.loads(OUT_PATH.read_text()):
            results[r["slug"]] = r

    by_repo: dict[str, list] = defaultdict(list)
    for s in samples:
        by_repo[s["clone_dir"]].append(s)

    print(f"Processing {len(samples)} slugs across {len(by_repo)} repos (serial per repo)")

    total = len(samples)
    done  = 0

    for clone_dir, repo_samples in sorted(by_repo.items()):
        todo = [s for s in repo_samples
                if not (args.resume and s["slug"] in results)]
        done += len(repo_samples) - len(todo)
        if not todo:
            continue

        build_command = get_build_command(Path(clone_dir))
        if build_command is None:
            for s in todo:
                done += 1
                print(f"  [{done}/{total}] {s['slug']}  ({s['function_name']})")
                print(f"    → ERR:no_build_system")
                results[s["slug"]] = {"slug": s["slug"], "hit_in_target_file": None,
                                       "error": "no_build_system"}
                OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))
            continue

        for s in todo:
            done += 1
            print(f"  [{done}/{total}] {s['slug']}  ({s['function_name']})")
            r = run_codeql_on_slug(s, build_command)
            results[s["slug"]] = r
            status = ("HIT_FILE" if r.get("hit_in_target_file") else
                      "HIT_REPO" if r.get("hit_anywhere") else
                      "MISS"     if r.get("hit_in_target_file") is False else
                      f"ERR:{r.get('error','')[:80]}")
            print(f"    → {status}  (total_hits={r.get('total_hits', '?')})")
            OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
            OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

    n        = len(results)
    hit_file = sum(1 for v in results.values() if v.get("hit_in_target_file") is True)
    hit_any  = sum(1 for v in results.values() if v.get("hit_anywhere") is True)
    errors   = sum(1 for v in results.values() if v.get("error"))

    print(f"""
=== CodeQL UseAfterFree.ql / traced build (N={n}) ===
  hit in target file              : {hit_file}/{n}  ({100*hit_file/n:.1f}%)
  hit anywhere in repo            : {hit_any}/{n}  ({100*hit_any/n:.1f}%)
  errors / timeouts                : {errors}
Results → {OUT_PATH}""")


if __name__ == "__main__":
    main()
