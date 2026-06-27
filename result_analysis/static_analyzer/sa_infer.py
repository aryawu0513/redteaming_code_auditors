"""
Infer v1.1.0 catch-rate on 128 CVE NPD samples.
Uses each repo's build system to generate compile_commands.json,
then runs Infer via --compilation-database.

Build system strategies (tried in order per repo):
  1. Existing _cmake_build/ → re-run cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON (fast, no rebuild)
  2. CMakeLists.txt at root → fresh cmake configure in cache dir
  3. autoconf/Makefile     → bear -- make -B -j4 -k (force rebuild, intercept compiler calls)

bear 3.0.18 is extracted from a local container image layer (no sudo needed):
  BEAR_LAYER points to the overlay dir containing /usr/bin/bear and its libs.

Each slug patches its target file with the vulnerable version,
runs Infer, then restores the original. Slugs sharing the same
repo run SERIALLY to avoid concurrent file conflicts.

Usage:
    python result_analysis/sa_infer.py [--resume]

Output:
    result_analysis/sa_infer.json
"""

import json
import os
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

BENCH_ROOT  = Path("/mnt/ssd/aryawu/redteaming_code_auditors/benchmark/cvebench_full/baseline")
MANIFEST    = Path("/mnt/ssd/aryawu/cve_repos_infer/clone_manifest.json")
OUT_PATH    = Path(__file__).parent / "sa_infer.json"
COMPILE_DB_CACHE = Path("/tmp/cve_sa_compile_dbs")
INFER       = "/mnt/ssd/aryawu/infer-linux64-v1.1.0/bin/infer"
CMAKE       = "/usr/bin/cmake"

# bear 3.0.18 from container image layer — all deps present in same layer
BEAR_LAYER  = Path("/mnt/ssd/aryawu/.local/share/containers/storage/overlay/"
                   "25a38ed902c37561c38cd13b726fc94ab7e643c1a5e27dd8287e8639fde067db/diff")
BEAR        = str(BEAR_LAYER / "usr/bin/bear")
BEAR_LIBDIR = str(BEAR_LAYER / "usr/lib/x86_64-linux-gnu")


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


def _run(cmd, cwd, timeout=300, extra_env=None):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, cwd=str(cwd), env=env)


def _cmake_export(src_dir: Path, build_dir: Path, cache_path: Path) -> Path | None:
    """Run cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON; copy result to cache_path."""
    build_dir.mkdir(parents=True, exist_ok=True)
    r = _run([CMAKE, str(src_dir),
              "-DCMAKE_BUILD_TYPE=Debug",
              "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
             cwd=build_dir, timeout=180)
    cc = build_dir / "compile_commands.json"
    if not cc.exists():
        print(f"    [cmake failed] {r.stderr[-200:]}")
        return None
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(cc, cache_path)
    return cache_path


def _bear_make(repo_path: Path, cache_path: Path) -> Path | None:
    """Run bear -- make -B -j4 -k; copy compile_commands.json to cache_path."""
    # -B forces rebuild so bear intercepts actual compiler invocations.
    # All bear helper paths must be explicit since bear is not system-installed.
    r = _run([BEAR,
              "--interceptor", str(BEAR_LAYER / "usr/bin/intercept"),
              "--library",     str(BEAR_LAYER / "usr/lib/x86_64-linux-gnu/bear/libexec.so"),
              "--citnames",    str(BEAR_LAYER / "usr/bin/citnames"),
              "--wrapper",     str(BEAR_LAYER / "usr/lib/x86_64-linux-gnu/bear/wrapper"),
              "--wrapper-dir", str(BEAR_LAYER / "usr/lib/x86_64-linux-gnu/bear/wrapper.d"),
              "--", "make", "-B", "-j4", "-k"],
             cwd=repo_path, timeout=600,
             extra_env={"LD_LIBRARY_PATH": BEAR_LIBDIR})
    cc = repo_path / "compile_commands.json"
    if not cc.exists():
        print(f"    [bear failed] {r.stderr[-200:]}")
        return None
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(cc, cache_path)
    return cache_path


def get_compile_db(repo_path: Path, repo_key: str) -> tuple[Path | None, str]:
    """Return (compile_commands.json path, method) for a repo."""
    cache_path = COMPILE_DB_CACHE / repo_key / "compile_commands.json"
    if cache_path.exists():
        return cache_path, "cached"

    # Strategy 0: compile_commands.json already in repo root (e.g. sqlite amalgamation)
    existing_cc = repo_path / "compile_commands.json"
    if existing_cc.exists():
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(existing_cc, cache_path)
        return cache_path, "existing-cc-json"

    # Strategy 1: existing _cmake_build/ — just re-export, no rebuild
    existing_build = repo_path / "_cmake_build"
    if existing_build.exists() and (existing_build / "CMakeCache.txt").exists():
        print(f"  [cmake-reexport] {repo_key}")
        p = _cmake_export(repo_path, existing_build, cache_path)
        if p:
            return p, "cmake-reexport"

    # Strategy 2: CMakeLists.txt at root — fresh cmake configure
    if (repo_path / "CMakeLists.txt").exists():
        build_dir = COMPILE_DB_CACHE / repo_key
        print(f"  [cmake-fresh] {repo_key}")
        p = _cmake_export(repo_path, build_dir, cache_path)
        if p:
            return p, "cmake-fresh"

    # Strategy 3: autoconf or plain Makefile — use bear
    has_autoconf = (repo_path / "configure").exists() or (repo_path / "configure.ac").exists()
    has_makefile = (repo_path / "Makefile").exists() or (repo_path / "GNUmakefile").exists()
    if has_autoconf or has_makefile:
        print(f"  [bear-make] {repo_key}")
        p = _bear_make(repo_path, cache_path)
        if p:
            return p, "bear"

    return None, "no-build-system"


def run_infer_on_slug(sample: dict, compile_db: Path) -> dict:
    slug      = sample["slug"]
    fn        = sample["function_name"]
    src       = sample["primary_file"]
    clone_dir = sample["clone_dir"]
    vuln_fp   = sample["vuln_file_path"]

    repo_path   = Path(clone_dir)
    target_file = repo_path / vuln_fp

    if not target_file.exists():
        return {"slug": slug, "hit_in_function": None,
                "error": f"file not found in repo: {vuln_fp}"}

    original    = target_file.read_text(errors="replace")
    results_dir = Path(tempfile.mkdtemp(prefix=f"infer_out_{slug}_"))

    try:
        target_file.write_text(src)

        proc = subprocess.run(
            [INFER, "run",
             "--compilation-database", str(compile_db),
             "--keep-going",
             "--results-dir", str(results_dir)],
            capture_output=True, text=True, timeout=600
        )

        report_path = results_dir / "report.json"
        if not report_path.exists():
            return {"slug": slug, "hit_in_function": None,
                    "error": f"no report.json: {proc.stderr[:300]}"}

        report    = json.loads(report_path.read_text())
        null_hits = [r for r in report if r.get("bug_type","") in
                     ("NULL_DEREFERENCE", "NULLPTR_DEREFERENCE")]
        in_func   = [r for r in null_hits if r.get("procedure") == fn]
        target_fname = Path(vuln_fp).name
        in_file   = [r for r in null_hits if target_fname in r.get("file", "")]

        return {
            "slug":               slug,
            "function_name":      fn,
            "hit_in_function":    bool(in_func),
            "hit_in_target_file": bool(in_file),
            "hit_anywhere":       bool(null_hits),
            "hits": [{"procedure": r.get("procedure"),
                      "file":      Path(r.get("file","")).name,
                      "line":      r.get("line")} for r in null_hits[:10]],
        }
    except subprocess.TimeoutExpired:
        return {"slug": slug, "hit_in_function": None, "error": "timeout"}
    except Exception as e:
        return {"slug": slug, "hit_in_function": None, "error": str(e)}
    finally:
        target_file.write_text(original)
        shutil.rmtree(results_dir, ignore_errors=True)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true",
                        help="Skip slugs already in output file (non-error only)")
    args = parser.parse_args()

    samples = load_samples()

    results: dict[str, dict] = {}
    if OUT_PATH.exists():
        for r in json.loads(OUT_PATH.read_text()):
            results[r["slug"]] = r

    by_repo: dict[str, list] = defaultdict(list)
    for s in samples:
        by_repo[s["clone_dir"]].append(s)

    print(f"Processing {len(samples)} slugs across {len(by_repo)} repos")
    print(f"bear: {BEAR}")

    total = len(samples)
    done  = 0

    for clone_dir, repo_samples in sorted(by_repo.items()):
        repo_key  = Path(clone_dir).name
        repo_path = Path(clone_dir)

        # When resuming, skip slugs that already have a non-error result
        todo = [s for s in repo_samples
                if not (args.resume and s["slug"] in results
                        and not results[s["slug"]].get("error"))]
        if not todo:
            done += len(repo_samples)
            continue

        compile_db, method = get_compile_db(repo_path, repo_key)
        if compile_db is None:
            for s in todo:
                results[s["slug"]] = {
                    "slug": s["slug"], "hit_in_function": None,
                    "error": f"no build system found ({method})"
                }
                done += 1
            OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
            OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))
            continue

        print(f"  compile_db via {method}: {compile_db}")

        for s in todo:
            done += 1
            print(f"  [{done}/{total}] {s['slug']}  ({s['function_name']})")
            r = run_infer_on_slug(s, compile_db)
            results[s["slug"]] = r
            status = ("HIT_FN"   if r.get("hit_in_function") else
                      "HIT_FILE" if r.get("hit_in_target_file") else
                      "HIT_REPO" if r.get("hit_anywhere") else
                      "MISS"     if r.get("hit_in_function") is False else
                      f"ERR:{r.get('error','')[:60]}")
            print(f"    → {status}")
            OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

    n        = len(results)
    hit_fn   = sum(1 for v in results.values() if v.get("hit_in_function") is True)
    hit_file = sum(1 for v in results.values() if v.get("hit_in_target_file") is True)
    hit_any  = sum(1 for v in results.values() if v.get("hit_anywhere") is True)
    errors   = sum(1 for v in results.values() if v.get("error"))

    print(f"""
=== Infer v1.1.0 (N={n}) ===
  NULL_DEREFERENCE in target function : {hit_fn}/{n}  ({100*hit_fn/n:.1f}%)
  NULL_DEREFERENCE in target file     : {hit_file}/{n}  ({100*hit_file/n:.1f}%)
  NULL_DEREFERENCE anywhere in repo   : {hit_any}/{n}  ({100*hit_any/n:.1f}%)
  errors / no compile_db              : {errors}
Results → {OUT_PATH}""")


if __name__ == "__main__":
    main()
