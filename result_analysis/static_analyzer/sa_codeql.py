"""
CodeQL MissingNullTest.ql catch-rate on 128 CVE NPD samples.
Uses build-mode=none (no compiler needed — syntactic C/C++ analysis).

Per-slug: patches target file with vulnerable version → builds DB → runs query → restores.
Slugs sharing the same repo run SERIALLY to avoid concurrent file conflicts.
The CodeQL DB is rebuilt for each slug (since the source file changes).

Usage:
    python scripts/oneoff/sa_codeql.py [--resume]

Output:
    results/sa_codeql.json
"""

import argparse
import json
import subprocess
import shutil
from collections import defaultdict
from pathlib import Path

BENCH_ROOT  = Path("/mnt/ssd/aryawu/redteaming_code_auditors/benchmark/cvebench_full/baseline")
MANIFEST    = Path("/mnt/ssd/aryawu/cve_repos_codeql/clone_manifest.json")
OUT_PATH    = Path(__file__).parent / "sa_codeql.json"
DB_ROOT     = Path("/tmp/cve_sa_codeql_dbs")

CODEQL = "/mnt/ssd/aryawu/codeql-home/codeql/codeql"
QUERY  = "/mnt/ssd/aryawu/.codeql/packages/codeql/cpp-queries/1.6.3/Critical/MissingNullTest.ql"


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


def build_db(repo_path: Path, db_path: Path, slug: str) -> bool:
    """Build CodeQL DB with build-mode=none. Returns True on success."""
    r = subprocess.run(
        [CODEQL, "database", "create", str(db_path),
         "--language=cpp",
         "--source-root", str(repo_path),
         "--build-mode=none",
         "--overwrite"],
        capture_output=True, text=True, timeout=600
    )
    if r.returncode != 0:
        print(f"    [db build failed] {r.stderr[-200:]}")
        return False
    return True


def run_query(db_path: Path, sarif_path: Path) -> list[dict]:
    """Run MissingNullTest.ql, return list of {uri, line} hits."""
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


def run_codeql_on_slug(sample: dict) -> dict:
    slug      = sample["slug"]
    fn        = sample["function_name"]
    src       = sample["primary_file"]
    clone_dir = sample["clone_dir"]
    vuln_fp   = sample["vuln_file_path"]

    if not clone_dir or not Path(clone_dir).exists():
        return {"slug": slug, "hit_in_target_file": None,
                "error": f"clone_dir missing: {clone_dir}"}

    repo_path   = Path(clone_dir)
    target_file = repo_path / vuln_fp
    if not target_file.exists():
        return {"slug": slug, "hit_in_target_file": None,
                "error": f"file not found: {vuln_fp}"}

    db_path   = DB_ROOT / f"{slug}_db"
    sarif_path = DB_ROOT / f"{slug}.sarif"
    DB_ROOT.mkdir(parents=True, exist_ok=True)

    original = target_file.read_text(errors="replace")
    try:
        target_file.write_text(src)

        if not build_db(repo_path, db_path, slug):
            return {"slug": slug, "hit_in_target_file": None, "error": "db_build_failed"}

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
        # Clean up DB to save disk space (they can be large)
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

    # Group by clone_dir — serial within each repo to avoid concurrent patches
    by_repo: dict[str, list] = defaultdict(list)
    for s in samples:
        by_repo[s["clone_dir"]].append(s)

    print(f"Processing {len(samples)} slugs across {len(by_repo)} repos (serial per repo)")

    total = len(samples)
    done  = 0

    for clone_dir, repo_samples in sorted(by_repo.items()):
        repo_key = Path(clone_dir).name
        todo = [s for s in repo_samples
                if not (args.resume and s["slug"] in results)]
        if not todo:
            done += len(repo_samples)
            continue

        for s in todo:
            done += 1
            print(f"  [{done}/{total}] {s['slug']}  ({s['function_name']})")
            r = run_codeql_on_slug(s)
            results[s["slug"]] = r
            status = ("HIT_FILE" if r.get("hit_in_target_file") else
                      "HIT_REPO" if r.get("hit_anywhere") else
                      "MISS"     if r.get("hit_in_target_file") is False else
                      f"ERR:{r.get('error','')[:50]}")
            print(f"    → {status}  (total_hits={r.get('total_hits', '?')})")
            OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
            OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

    n        = len(results)
    hit_file = sum(1 for v in results.values() if v.get("hit_in_target_file") is True)
    hit_any  = sum(1 for v in results.values() if v.get("hit_anywhere") is True)
    errors   = sum(1 for v in results.values() if v.get("error"))

    print(f"""
=== CodeQL MissingNullTest.ql / build-mode=none (N={n}) ===
  hit in target file              : {hit_file}/{n}  ({100*hit_file/n:.1f}%)
  hit anywhere in repo            : {hit_any}/{n}  ({100*hit_any/n:.1f}%)
  errors / timeouts               : {errors}
Results → {OUT_PATH}""")


if __name__ == "__main__":
    main()
