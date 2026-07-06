#!/usr/bin/env python3
"""
Filter CWE-476 (NPD, default) or CWE-416 (UAF) C/C++ entries from MegaVul
down to viable benchmark candidates.

This is exactly the filter described in the paper's Benchmark Construction
paragraph: starting from MegaVul, retain only entries with the target CWE
ID, a single-file fix, a non-trivial function body, and a fetchable
upstream source. Nothing else — no compile check, no line-count cap, no
detector confirmation. The compatibility oracle (clone the repo at the fix
commit, run the real build and test suite) is a separate, already
CWE-agnostic stage: see check_repo_testsuite.py.

  Filter 1: single file touch      (free — uses diff_stats from dataset)
  Filter 2: non-trivial function body (free — uses diff_stats from dataset)
  Filter 3: fetchable upstream source (fetch full file from GitHub)

  --dedup and --assign-ids are housekeeping, not filters. --dedup drops
  literal duplicate rows sharing (cve_id, func_name, vulnerable_code) — a
  single CVE fix commit legitimately touching several functions is real and
  kept (same as NPD), but MegaVul's raw stream can also contain the exact
  same row more than once. --assign-ids gives every row a unique pilot_id,
  required by every downstream stage (check_repo_testsuite.py,
  extract_context_cve.py, generate_task_only.py, judge_cve_new.py,
  build_benchmark.py).

Run stages separately so you can inspect survivors at each step:

  python filter_pipeline.py --filter12 --out f12.jsonl
  python filter_pipeline.py --filter3  --in f12.jsonl --out f3.jsonl [--token TOKEN]
  python filter_pipeline.py --dedup --in f3.jsonl --out f3_dedup.jsonl
  python filter_pipeline.py --assign-ids --in f3_dedup.jsonl --out f3_ids.jsonl

  # UAF instead of the default NPD:
  python filter_pipeline.py --filter12 --cwe 416 --out f12_uaf.jsonl
  python filter_pipeline.py --filter3  --in f12_uaf.jsonl --out f3_uaf.jsonl
  python filter_pipeline.py --dedup --in f3_uaf.jsonl --out f3_uaf_dedup.jsonl
  python filter_pipeline.py --assign-ids --cwe 416 --in f3_uaf_dedup.jsonl --out f3_uaf_ids.jsonl

  # Inspect raw schema:
  python filter_pipeline.py --probe

Dataset: hitoshura25/megavul (function-level, has file_paths + diff_stats)

Requires: pip install datasets
Optional:  GITHUB_TOKEN env var for higher rate limit in filter 3
"""

import argparse
import json
import os
import re
import time
import urllib.request
from pathlib import Path

HF_DATASET = "hitoshura25/megavul"
C_LANGS    = {"C", "C++", "c", "c++"}
C_EXTS     = {".c", ".cc", ".cpp", ".cxx"}   # implementation files only
HEADER_EXTS = {".h", ".hpp", ".hh", ".hxx"}  # always rejected

SUPPORTED_CWES = {476, 416}  # 476 = NPD, 416 = UAF


# ── MegaVul field parsing ─────────────────────────────────────────────────────

def _parse_json_field(row, key):
    """hitoshura25/megavul stores file_paths and diff_stats as JSON strings."""
    val = row.get(key)
    if val is None:
        return None
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return val


def get_file_paths(row) -> list[str]:
    """Return list of file paths touched by the fix commit."""
    fps = _parse_json_field(row, "file_paths")
    if isinstance(fps, list):
        return fps
    return []


def get_lines_added(row) -> int:
    """Sum lines_added across all files in diff_stats."""
    ds = _parse_json_field(row, "diff_stats")
    if not isinstance(ds, dict):
        return -1
    return sum(v.get("lines_added", 0) for v in ds.values())


def parse_repo_url(row) -> tuple[str, str]:
    """
    row["repo_url"] is the commit URL like
    https://github.com/owner/repo/commit/<hash>
    Returns (plain_repo_url, fix_commit_hash).
    """
    url = row.get("repo_url", "")
    m = re.match(r"(https://github\.com/[^/]+/[^/]+?)/commit/([0-9a-f]+)$", url)
    if m:
        return m.group(1), m.group(2)
    # fallback: no commit embedded
    m2 = re.match(r"(https://github\.com/[^/]+/[^/]+)", url)
    return (m2.group(1) if m2 else url), ""


def get_func_name(row) -> str:
    """Extract function name from vulnerable_code.

    Scans up to the first opening brace so multi-line signatures like
        static void
        my_func(args)  { ...
    and macro-wrapped signatures like
        METHODDEF(void)
        start_pass(j_decompress_ptr cinfo) { ...
    are handled correctly.  Returns the last identifier before '('.
    """
    fn = (row.get("vulnerable_code") or "").strip()
    # Take only the signature part (before the first '{')
    sig = fn.split("{", 1)[0] if fn else ""
    # Find all word(paren pairs; the last one before the body is the function name
    matches = re.findall(r'\b([a-zA-Z_]\w*)\s*\(', sig)
    # Filter out keywords and common macro names
    skip = {"if", "while", "for", "switch", "return", "sizeof",
            "METHODDEF", "GLOBAL", "LOCAL", "JMETHOD"}
    for name in reversed(matches):
        if name not in skip:
            return name
    return ""


def matches_cwe(row, cwe: int) -> bool:
    """True if row['cwe_id'] contains CWE-<cwe> (e.g. 476=NPD, 416=UAF)."""
    tag = f"CWE-{cwe}"
    cwe_field = row.get("cwe_id", "")
    if isinstance(cwe_field, list):
        return tag in cwe_field
    return tag in (cwe_field or "")


def is_c_cpp(row) -> bool:
    fps = get_file_paths(row)
    ext = Path(fps[0]).suffix.lower() if fps else ""
    # Always reject header files — the bug must be in an implementation file
    if ext in HEADER_EXTS:
        return False
    lang = row.get("language", "")
    if lang in C_LANGS:
        return True
    return ext in C_EXTS


def count_body_statements(code: str) -> int:
    """Count meaningful lines in a function body.

    Strips blank lines, braces-only lines, comment lines, and the signature.
    Counts lines that have: semicolons, pointer ops, return, or control flow.
    Threshold ≥ 2 rejects pure 1-liner delegations like
        return get_decoratee().init_env(cct);
    while keeping single-statement-but-complex bodies like
        (*vt->allocator->free)(ptr, vt->allocdata);   [has ->]
    """
    lines = code.strip().splitlines()
    # Find body start: first standalone '{' line (not on signature line)
    body_start = 0
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if stripped == '{':
            body_start = i + 1
            break
        if '{' in stripped and '(' not in stripped:
            body_start = i + 1
            break
    body = lines[body_start:]
    count = 0
    for ln in body:
        s = ln.strip()
        if not s or s in ('{', '}'):
            continue
        if s.startswith(('/*', '*', '//')):
            continue
        if any(tok in s for tok in (';', '->', '(*', 'return ',
                                     'if ', 'if(', 'while ', 'for ',
                                     'switch', 'else')):
            count += 1
    return count


def normalize(row) -> dict:
    fps              = get_file_paths(row)
    repo_url, fxcmt  = parse_repo_url(row)
    return {
        "source":          "megavul",
        "cve_id":          row.get("cve_id", ""),
        "repo_url":        repo_url,
        "commit_hash":     fxcmt,   # fix commit — file is reachable at this ref
        "file_path":       fps[0] if fps else "",
        "func_name":       get_func_name(row),
        "commit_message":  row.get("commit_message", ""),
        "vulnerable_code": row.get("vulnerable_code", ""),
        # internal — stripped before writing candidate.json
        "_fixed_code":     row.get("fixed_code", ""),
        "_file_paths":     fps,
    }


# ── Filter 1+2 (streaming, no GitHub calls) ──────────────────────────────────
#
# Filter 1: single-file fix.
# Filter 2: non-trivial function body (checked on both vulnerable_code and
#           fixed_code, so a fix that reduces the function to a stub is also
#           rejected — an extracted context that trivial is useless as a task).

def run_filter12(out_path: str, limit: int, cwe: int = 476):
    from datasets import load_dataset

    print(f"Streaming {HF_DATASET} (CWE-{cwe}) …")
    ds = load_dataset(HF_DATASET, split="train", streaming=True)

    counts = dict(total=0, cwe_match=0, c_cpp=0, has_vuln_code=0,
                  f1_pass=0, f2_pass=0, written=0,
                  f1_skip_no_files=0, f1_skip_multi=0,
                  f2_skip_trivial=0)

    with open(out_path, "w") as fout:
        for row in ds:
            counts["total"] += 1

            if not matches_cwe(row, cwe):
                continue
            counts["cwe_match"] += 1

            if not is_c_cpp(row):
                continue
            counts["c_cpp"] += 1

            # Drop rows where the pre-patch function wasn't recovered
            if not row.get("vulnerable_code"):
                continue
            counts["has_vuln_code"] += 1

            rec = normalize(row)
            fps = rec["_file_paths"]

            # Filter 1: exactly one file touched
            if not fps:
                counts["f1_skip_no_files"] += 1
                continue
            if len(fps) != 1:
                counts["f1_skip_multi"] += 1
                continue
            counts["f1_pass"] += 1

            # Filter 2: reject trivially small function bodies
            body_stmts_vuln  = count_body_statements(rec["vulnerable_code"])
            body_stmts_fixed = count_body_statements(rec.get("_fixed_code", ""))
            if body_stmts_vuln < 2 or body_stmts_fixed < 2:
                counts["f2_skip_trivial"] += 1
                continue
            counts["f2_pass"] += 1

            # Record lines_added for viewer display (informational only, not a filter)
            rec["_lines_added"] = get_lines_added(row)
            fout.write(json.dumps(rec) + "\n")
            counts["written"] += 1

            if counts["total"] % 5000 == 0:
                print(f"  … {counts['total']} rows | cwe_match={counts['cwe_match']} "
                      f"c/cpp={counts['c_cpp']} f1={counts['f1_pass']} "
                      f"f2={counts['f2_pass']} written={counts['written']}")

            if limit and counts["written"] >= limit:
                print(f"  (stopped early at --limit {limit})")
                break

    print(f"\nFilter 1+2 complete:")
    print(f"  Total rows         {counts['total']}")
    print(f"  CWE-{cwe}            {counts['cwe_match']}")
    print(f"  C/C++              {counts['c_cpp']}")
    print(f"  has vulnerable_code {counts['has_vuln_code']}")
    print(f"  → F1 pass          {counts['f1_pass']}  "
          f"(skipped: {counts['f1_skip_no_files']} no-files, "
          f"{counts['f1_skip_multi']} multi-file)")
    print(f"  → F2 pass          {counts['f2_pass']}  "
          f"(skipped: {counts['f2_skip_trivial']} trivial body <2 stmts)")
    print(f"  Survivors          {counts['written']}  → {out_path}")


# ── Filter 3 (fetchable upstream source) ─────────────────────────────────────
#
# Just confirms the file is fetchable from GitHub at the fix commit. No
# compile check, no line-count cap — those aren't part of this filter; the
# real compatibility oracle is check_repo_testsuite.py (clone + build + test
# the whole repo), a separate, later stage.

def _github_raw_url(repo_url: str, commit: str, file_path: str) -> str:
    m = re.match(r"https://github\.com/([^/]+/[^/]+)", repo_url)
    if not m:
        return ""
    owner_repo = m.group(1).rstrip(".git")
    return f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{file_path.lstrip('/')}"


def fetch_url(url: str, token: str | None) -> str | None:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"token {token}")
    req.add_header("User-Agent", "cve-filter-pipeline/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def run_filter3(in_path: str, out_path: str, token: str | None, limit: int,
                skip_existing: bool = False):
    lines = Path(in_path).read_text().splitlines()
    total = len(lines)
    print(f"\nFilter 3: {total} candidates from {in_path}")
    if not token:
        print("WARNING: no GitHub token — rate-limited to ~60 req/hr. "
              "Set GITHUB_TOKEN or pass --token.")

    # Build skip set from existing output to avoid re-fetching already-done entries
    existing_keys: set[tuple] = set()
    if skip_existing and Path(out_path).exists():
        for el in Path(out_path).read_text().splitlines():
            r = json.loads(el)
            existing_keys.add((r["cve_id"], r["func_name"]))
        print(f"  skipping {len(existing_keys)} already-fetched entries")

    delay   = 0.05 if token else 0.72
    counts  = dict(fetch_ok=0, skipped_existing=0)
    written = len(existing_keys)

    open_mode = "a" if skip_existing and existing_keys else "w"
    with open(out_path, open_mode) as fout:
        for i, line in enumerate(lines):
            rec = json.loads(line)
            tag = f"[{i+1}/{total}]"

            if (rec["cve_id"], rec["func_name"]) in existing_keys:
                counts["skipped_existing"] += 1
                continue

            url = _github_raw_url(rec["repo_url"], rec["commit_hash"], rec["file_path"])
            if not url:
                print(f"  {tag} SKIP (bad URL): {rec['repo_url']}")
                continue

            time.sleep(delay)
            content = fetch_url(url, token)
            if content is None:
                print(f"  {tag} FETCH FAIL: {url}")
                continue
            counts["fetch_ok"] += 1

            rec["full_file"] = content
            fout.write(json.dumps(rec) + "\n")
            written += 1
            print(f"  {tag} OK ({len(content.splitlines())} lines, "
                  f"+{rec.get('_lines_added','?')} added): {rec['file_path']}")

            if limit and written >= limit:
                print(f"  (stopped early at --limit {limit})")
                break

    print(f"\nFilter 3 complete:")
    for k, v in counts.items():
        print(f"  {k:<15} {v}")
    print(f"  Survivors  {written}  → {out_path}")


# ── Dedup (housekeeping, not a filter) ───────────────────────────────────────
#
# MegaVul's raw stream can contain literal duplicate rows for the same
# (cve_id, func_name, vulnerable_code) — not a legitimate multi-function CVE
# (a single fix commit touching several functions is real and kept, same as
# NPD), but the exact same row appearing more than once. Keeps the first
# occurrence of each (cve_id, func_name, vulnerable_code) key.

def run_dedup(in_path: str, out_path: str) -> None:
    lines = [l for l in Path(in_path).read_text().splitlines() if l.strip()]
    seen: set[tuple] = set()
    written = 0
    with open(out_path, "w") as fout:
        for line in lines:
            rec = json.loads(line)
            key = (rec.get("cve_id", ""), rec.get("func_name", ""), rec.get("vulnerable_code", ""))
            if key in seen:
                continue
            seen.add(key)
            fout.write(json.dumps(rec) + "\n")
            written += 1
    print(f"Dedup: {len(lines)} rows → {written} unique (cve_id, func_name, vulnerable_code) → {out_path}")


# ── Assign pilot IDs (housekeeping, not a filter) ────────────────────────────
#
# Every downstream stage (check_repo_testsuite.py, extract_context_cve.py,
# generate_task_only.py, judge_cve_new.py, build_benchmark.py) requires a
# unique "pilot_id" per row, e.g. "NPD-CVE-0001". filter3's output has none —
# assign them here, once, right after filter3 (and after --dedup, if used).

def run_assign_ids(in_path: str, out_path: str, prefix: str) -> None:
    lines = [l for l in Path(in_path).read_text().splitlines() if l.strip()]
    with open(out_path, "w") as fout:
        for i, line in enumerate(lines):
            rec = json.loads(line)
            rec["pilot_id"] = f"{prefix}-{i+1:04d}"
            fout.write(json.dumps(rec) + "\n")
    print(f"Assigned {len(lines)} pilot_ids ({prefix}-0001 … {prefix}-{len(lines):04d}) → {out_path}")


# ── Probe ─────────────────────────────────────────────────────────────────────

def run_probe():
    from datasets import load_dataset
    print(f"Probing {HF_DATASET} — first 3 rows:")
    ds = load_dataset(HF_DATASET, split="train", streaming=True)
    for i, row in enumerate(ds):
        print(f"\n── Row {i} ──")
        for k, v in row.items():
            preview = repr(v[:200]) if isinstance(v, str) else repr(v)[:120]
            print(f"  {k:<30} {preview}")
        if i >= 2:
            break


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probe",    action="store_true",
                    help="Print first 3 rows and exit")
    ap.add_argument("--filter12", action="store_true",
                    help="Run filters 1+2 (streaming, no GitHub)")
    ap.add_argument("--filter3",  action="store_true",
                    help="Run filter 3 (fetchable upstream source)")
    ap.add_argument("--dedup",    action="store_true",
                    help="Drop literal duplicate rows sharing (cve_id, func_name, "
                         "vulnerable_code) — run this after --filter3, before --assign-ids")
    ap.add_argument("--assign-ids", action="store_true",
                    help="Assign sequential pilot_id to each row (required before "
                         "check_repo_testsuite.py and every later stage)")
    ap.add_argument("--cwe", type=int, default=476, choices=sorted(SUPPORTED_CWES),
                    help="Which CWE to mine: 476 (NPD, default) or 416 (UAF). "
                         "Used by --filter12.")
    ap.add_argument("--prefix", default=None,
                    help="pilot_id prefix for --assign-ids, e.g. NPD-CVE or UAF-CVE "
                         "(default: derived from --cwe)")
    ap.add_argument("--in",  dest="in_path",  help="Input JSONL (filter3/assign-ids)")
    ap.add_argument("--out", dest="out_path", help="Output file")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"),
                    help="GitHub token (default: $GITHUB_TOKEN)")
    ap.add_argument("--limit", type=int, default=0,
                    help="Stop after N survivors (for testing)")
    ap.add_argument("--skip-existing", action="store_true",
                    help="Append to --out, skipping entries already present (resume)")
    args = ap.parse_args()

    if args.probe:
        run_probe()
    elif args.filter12:
        if not args.out_path:
            ap.error("--filter12 requires --out")
        run_filter12(args.out_path, args.limit, cwe=args.cwe)
    elif args.filter3:
        if not args.in_path or not args.out_path:
            ap.error("--filter3 requires --in and --out")
        run_filter3(args.in_path, args.out_path, args.token, args.limit,
                    skip_existing=args.skip_existing)
    elif args.dedup:
        if not args.in_path or not args.out_path:
            ap.error("--dedup requires --in and --out")
        run_dedup(args.in_path, args.out_path)
    elif args.assign_ids:
        if not args.in_path or not args.out_path:
            ap.error("--assign-ids requires --in and --out")
        prefix = args.prefix or ("NPD-CVE" if args.cwe == 476 else "UAF-CVE")
        run_assign_ids(args.in_path, args.out_path, prefix)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
