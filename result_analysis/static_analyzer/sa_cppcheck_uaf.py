"""
CppCheck catch-rate on the 70 judge-confirmed CVE UAF samples.
UAF counterpart of sa_cppcheck.py. Filters on cppcheck's CWE-416/415
checks (deallocuse, doubleFree) instead of NPD's nullPointer.

Runs CppCheck on the FULL repo directory (not just primary_file) so that
project headers and includes are resolved, enabling the full checker set.
For each slug: patches the target file with the vulnerable version, runs
CppCheck on the repo root, checks for deallocuse/doubleFree findings in the
target file/function, then restores the original.

Slugs sharing the same repo run SERIALLY to avoid concurrent file conflicts.
CppCheck is compile-free so no build setup is needed.

Usage:
    python result_analysis/static_analyzer/sa_cppcheck_uaf.py [--resume]

Output:
    result_analysis/static_analyzer/sa_cppcheck_uaf.json
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
import subprocess

BENCH_ROOT = Path("/mnt/ssd/aryawu/redteaming_code_auditors/benchmark/cvebench_full_uaf/baseline")
MANIFEST   = Path(__file__).parent / "uaf_clone_manifest.json"
OUT_PATH   = Path(__file__).parent / "sa_cppcheck_uaf.json"
CPPCHECK   = "cppcheck"

# cppcheck's CWE-416 (use-after-free) and CWE-415 (double-free) check IDs.
UAF_IDS = ("deallocuse", "doubleFree")


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


def find_function_line_range(source: str, function_name: str):
    """Return (start_line, end_line) 1-indexed. Handles multi-line signatures."""
    lines = source.splitlines()
    start      = None
    depth      = 0
    seen_open  = False
    for i, line in enumerate(lines, 1):
        if start is None and re.search(rf'\b{re.escape(function_name)}\s*\(', line):
            start = i
        if start is not None:
            depth += line.count('{') - line.count('}')
            if depth > 0:
                seen_open = True
            if seen_open and depth <= 0:
                return start, i
    return start or 1, len(lines)


def run_cppcheck_on_repo(sample: dict) -> dict:
    slug      = sample["slug"]
    fn        = sample["function_name"]
    src       = sample["primary_file"]
    clone_dir = sample["clone_dir"]
    vuln_fp   = sample["vuln_file_path"]

    if not clone_dir or not Path(clone_dir).exists():
        return {"slug": slug, "hit_in_function": None,
                "error": f"clone_dir missing: {clone_dir}"}

    repo_path   = Path(clone_dir)
    target_file = repo_path / vuln_fp
    if not target_file.exists():
        return {"slug": slug, "hit_in_function": None,
                "error": f"file not in repo: {vuln_fp}"}

    original = target_file.read_text(errors="replace")
    try:
        target_file.write_text(src)

        # No --enable=warning,style / --inconclusive: deallocuse and doubleFree
        # are both severity="error" (cppcheck's core, always-on check category),
        # so they fire without those flags. Dropping them skips the far more
        # expensive style/inconclusive analysis passes, which is what made
        # large repos (e.g. ghostpdl) time out. -j4 parallelizes across files.
        proc = subprocess.run(
            [CPPCHECK,
             "-j4",
             "--quiet",
             "--suppress=unknownMacro",
             "--suppress=missingInclude",
             "--suppress=missingIncludeSystem",
             "--template={file}:{line}:{column}: {severity}: {message} [{id}]",
             str(repo_path)],
            capture_output=True, text=True, timeout=1800
        )
        output = proc.stderr + proc.stdout

        id_pattern = "|".join(UAF_IDS)
        all_uaf: list[tuple[str, int, str]] = []
        for m in re.finditer(rf'([^:]+):(\d+):\d+: \w+:.*\[({id_pattern})\]', output):
            all_uaf.append((m.group(1), int(m.group(2)), m.group(3)))

        target_fname = Path(vuln_fp).name
        in_file = [(f, l, cid) for f, l, cid in all_uaf if target_fname in f]

        fstart, fend = find_function_line_range(src, fn)
        in_func = [(f, l, cid) for f, l, cid in in_file if fstart <= l <= fend]

        return {
            "slug":                 slug,
            "function_name":        fn,
            "hit_in_function":      bool(in_func),
            "hit_in_target_file":   bool(in_file),
            "hit_anywhere":         bool(all_uaf),
            "func_range":           [fstart, fend],
            "warnings_in_func":     in_func,
            "warnings_in_file":     in_file,
            "total_uaf_warnings":   len(all_uaf),
        }
    except subprocess.TimeoutExpired:
        return {"slug": slug, "hit_in_function": None, "error": "timeout"}
    except Exception as e:
        return {"slug": slug, "hit_in_function": None, "error": str(e)}
    finally:
        target_file.write_text(original)


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
        if not todo:
            done += len(repo_samples)
            continue

        for s in todo:
            done += 1
            print(f"  [{done}/{total}] {s['slug']}  ({s['function_name']})")
            r = run_cppcheck_on_repo(s)
            results[s["slug"]] = r
            status = ("HIT_FN"   if r.get("hit_in_function") else
                      "HIT_FILE" if r.get("hit_in_target_file") else
                      "HIT_REPO" if r.get("hit_anywhere") else
                      "MISS"     if r.get("hit_in_function") is False else
                      f"ERR:{r.get('error','')[:50]}")
            print(f"    → {status}  (uaf_warnings={r.get('total_uaf_warnings','?')})")
            OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
            OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

    n        = len(results)
    hit_fn   = sum(1 for v in results.values() if v.get("hit_in_function") is True)
    hit_file = sum(1 for v in results.values() if v.get("hit_in_target_file") is True)
    hit_any  = sum(1 for v in results.values() if v.get("hit_anywhere") is True)
    errors   = sum(1 for v in results.values() if v.get("error"))

    print(f"""
=== CppCheck deallocuse/doubleFree (full-repo, N={n}) ===
  hit IN target function           : {hit_fn}/{n}  ({100*hit_fn/n:.1f}%)
  hit in target file               : {hit_file}/{n}  ({100*hit_file/n:.1f}%)
  hit anywhere in repo             : {hit_any}/{n}  ({100*hit_any/n:.1f}%)
  errors / timeouts                : {errors}
Results → {OUT_PATH}""")


if __name__ == "__main__":
    main()
