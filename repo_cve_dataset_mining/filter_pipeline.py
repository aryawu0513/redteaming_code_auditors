#!/usr/bin/env python3
"""
Filter CWE-476 (NPD) C/C++ entries from MegaVul down to viable benchmark
candidates. Four filters applied in order of cheapness:

  Filter 1: single file touch   (free — uses diff_stats from dataset)
  Filter 2: <=5 lines added     (free — uses diff_stats from dataset)
  Filter 3: fetch full file from GitHub, check <1000 lines + compiles
  Filter 4: CodeQL cpp/missing-null-test must fire
  Filter 5: reasoning pointer coverage (free — checks reasoning against diff)

Run stages separately so you can inspect survivors at each step:

  python filter_pipeline.py --filter12 --out f12.jsonl
  python filter_pipeline.py --filter3  --in f12.jsonl --out f3.jsonl [--token TOKEN]
  python filter_pipeline.py --filter4  --in f3.jsonl  --out candidates/
  python filter_pipeline.py --filter5  --in f3_dedup.jsonl --results f3_dedup.results.jsonl --out f3_dedup.f5.jsonl

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
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HF_DATASET = "hitoshura25/megavul"
C_LANGS    = {"C", "C++", "c", "c++"}
C_EXTS     = {".c", ".cc", ".cpp", ".cxx"}   # implementation files only
HEADER_EXTS = {".h", ".hpp", ".hh", ".hxx"}  # always rejected


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


def is_npd(row) -> bool:
    cwe = row.get("cwe_id", "")
    # field is a string, but guard against list too
    if isinstance(cwe, list):
        return "CWE-476" in cwe
    return "CWE-476" in (cwe or "")


def is_c_cpp(row) -> bool:
    fps = get_file_paths(row)
    ext = Path(fps[0]).suffix.lower() if fps else ""
    # Always reject header files — NPD bugs must be in implementation files
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

def run_filter12(out_path: str, limit: int):
    from datasets import load_dataset

    print(f"Streaming {HF_DATASET} …")
    ds = load_dataset(HF_DATASET, split="train", streaming=True)

    counts = dict(total=0, npd=0, c_cpp=0, has_vuln_code=0,
                  f1_pass=0, f2_pass=0, written=0,
                  f1_skip_no_files=0, f1_skip_multi=0,
                  f2_skip_trivial=0)

    with open(out_path, "w") as fout:
        for row in ds:
            counts["total"] += 1

            if not is_npd(row):
                continue
            counts["npd"] += 1

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

            # Filter 2: reject trivially small function bodies.
            # Check both versions: vulnerable_code catches pure delegations;
            # fixed_code catches cases where the fix reduced the function to a
            # stub (e.g. crypto_rng_init_tfm → return 0), making the extracted
            # context useless as a benchmark item.
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
                print(f"  … {counts['total']} rows | npd={counts['npd']} "
                      f"c/cpp={counts['c_cpp']} f1={counts['f1_pass']} "
                      f"f2={counts['f2_pass']} written={counts['written']}")

            if limit and counts["written"] >= limit:
                print(f"  (stopped early at --limit {limit})")
                break

    print(f"\nFilter 1+2 complete:")
    print(f"  Total rows         {counts['total']}")
    print(f"  CWE-476            {counts['npd']}")
    print(f"  C/C++              {counts['c_cpp']}")
    print(f"  has vulnerable_code {counts['has_vuln_code']}")
    print(f"  → F1 pass          {counts['f1_pass']}  "
          f"(skipped: {counts['f1_skip_no_files']} no-files, "
          f"{counts['f1_skip_multi']} multi-file)")
    print(f"  → F2 pass          {counts['f2_pass']}  "
          f"(skipped: {counts['f2_skip_trivial']} trivial body <2 stmts)")
    print(f"  Survivors          {counts['written']}  → {out_path}")


# ── Filter 3 (GitHub fetch + compile check) ───────────────────────────────────

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
    req.add_header("User-Agent", "npd-filter-pipeline/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def try_compile(src: str, suffix: str) -> bool:
    """
    Return True if the file has no actual syntax errors.
    Missing-header errors (No such file or directory) are accepted —
    almost every real-world file needs project headers we don't have.
    """
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w") as f:
        f.write(src)
        fname = f.name
    compiler = "g++" if suffix in (".cpp", ".cc", ".cxx", ".hpp") else "gcc"
    try:
        r = subprocess.run(
            [compiler, "-c", "-fsyntax-only", "-w", fname],
            capture_output=True, timeout=10,
        )
        if r.returncode == 0:
            return True
        stderr = r.stderr.decode(errors="replace")
        # Only real syntax errors should disqualify — missing includes are fine
        syntax_errors = [
            ln for ln in stderr.splitlines()
            if ": error:" in ln and "No such file or directory" not in ln
        ]
        return len(syntax_errors) == 0
    except Exception:
        return False
    finally:
        os.unlink(fname)


def run_filter3(in_path: str, out_path: str, token: str | None, limit: int):
    lines = Path(in_path).read_text().splitlines()
    total = len(lines)
    print(f"\nFilter 3: {total} candidates from {in_path}")
    if not token:
        print("WARNING: no GitHub token — rate-limited to ~60 req/hr. "
              "Set GITHUB_TOKEN or pass --token.")

    delay   = 0.05 if token else 0.72
    counts  = dict(fetch_ok=0, size_ok=0, compile_ok=0)
    written = 0

    with open(out_path, "w") as fout:
        for i, line in enumerate(lines):
            rec    = json.loads(line)
            url    = _github_raw_url(rec["repo_url"], rec["commit_hash"], rec["file_path"])
            tag    = f"[{i+1}/{total}]"

            if not url:
                print(f"  {tag} SKIP (bad URL): {rec['repo_url']}")
                continue

            time.sleep(delay)
            content = fetch_url(url, token)
            if content is None:
                print(f"  {tag} FETCH FAIL: {url}")
                continue
            counts["fetch_ok"] += 1

            n_lines = len(content.splitlines())
            if n_lines > 2000:
                print(f"  {tag} TOO LARGE ({n_lines} lines): {rec['file_path']}")
                continue
            counts["size_ok"] += 1

            suffix = Path(rec["file_path"]).suffix.lower() or ".c"
            if not try_compile(content, suffix):
                print(f"  {tag} NO COMPILE: {rec['file_path']}")
                continue
            counts["compile_ok"] += 1

            rec["full_file"] = content
            fout.write(json.dumps(rec) + "\n")
            written += 1
            print(f"  {tag} OK ({n_lines} lines, +{rec.get('_lines_added','?')} added): "
                  f"{rec['file_path']}")

            if limit and written >= limit:
                print(f"  (stopped early at --limit {limit})")
                break

    print(f"\nFilter 3 complete:")
    for k, v in counts.items():
        print(f"  {k:<15} {v}")
    print(f"  Survivors  {written}  → {out_path}")


# ── Filter 4 (VulnLLM-R positive control) ────────────────────────────────────

VULNLLMR_URL = "http://localhost:8008"


def vulnllmr_detects(buggy_file: str, func_name: str,
                     file_path: str) -> bool:
    """Return True if VulnLLM-R flags the buggy file as vulnerable."""
    try:
        import requests
    except ImportError:
        print("WARNING: pip install requests — skipping VulnLLM-R check")
        return False
    body = {
        "code":            buggy_file,
        "context":         "",
        "target_function": buggy_file,
        "function_name":   func_name,
        "file_name":       Path(file_path).name,
    }
    try:
        r = requests.post(f"{VULNLLMR_URL}/detect", json=body, timeout=300)
        r.raise_for_status()
        return r.json().get("verdict") == "vulnerable"
    except Exception as e:
        print(f"(VulnLLM-R error: {e})")
        return False


def run_filter4(in_path: str, out_dir: str, limit: int):
    # Health-check the server first
    try:
        import requests
        requests.get(f"{VULNLLMR_URL}/health", timeout=5).raise_for_status()
        print(f"VulnLLM-R server OK at {VULNLLMR_URL}")
    except Exception as e:
        print(f"WARNING: VulnLLM-R not reachable ({e}) — filter4 will mark all as miss")

    lines = Path(in_path).read_text().splitlines()
    total = len(lines)
    print(f"\nFilter 4 (VulnLLM-R): {total} candidates from {in_path}")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    counts  = dict(hit=0, miss=0, error=0)
    written = 0

    for i, line in enumerate(lines):
        rec        = json.loads(line)
        fixed_file = rec.get("full_file", "")
        buggy_file = _make_buggy_file(
            fixed_file,
            rec.get("_fixed_code", ""),
            rec.get("vulnerable_code", ""),
        )
        tag = f"[{i+1}/{total}]"
        fn  = rec.get("func_name", "")
        fp  = rec.get("file_path", "")

        if buggy_file is None:
            print(f"  {tag} SKIP (reconstruction failed — fixed code not in full file): {fp}")
            counts["miss"] += 1
            continue

        print(f"  {tag} VulnLLM-R on {fp} ({fn}) …", end=" ", flush=True)
        if vulnllmr_detects(buggy_file, fn, fp):
            counts["hit"] += 1
            print("HIT")
            candidate = {k: v for k, v in rec.items() if not k.startswith("_")}
            candidate["full_file"] = buggy_file
            slug = (f"{candidate['source']}_{candidate['cve_id']}_"
                    f"{Path(fp).stem}")[:80].replace("/", "_")
            (Path(out_dir) / f"{slug}.json").write_text(
                json.dumps(candidate, indent=2))
            written += 1
        else:
            counts["miss"] += 1
            print("miss")

        if limit and written >= limit:
            print(f"  (stopped early at --limit {limit})")
            break

    print(f"\nFilter 4 complete:  hit={counts['hit']}  miss={counts['miss']}")
    print(f"{written} candidate.json files → {out_dir}/")


# ── CodeQL helpers (kept for reference / optional use) ───────────────────────

def find_codeql() -> str | None:
    for candidate in ["codeql", "/opt/codeql/codeql",
                      "/mnt/ssd/aryawu/codeql-home/codeql/codeql"]:
        try:
            r = subprocess.run([candidate, "version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return candidate
        except FileNotFoundError:
            continue
    return None


def _make_buggy_file(full_file: str, fixed_code: str, vulnerable_code: str) -> str | None:
    """Replace the fixed function with the vulnerable one in the full file.
    Returns None if reconstruction fails (fixed_code not found in full_file),
    which means the entry should be skipped — we can't verify the NPD state.
    """
    if fixed_code and fixed_code.strip() in full_file:
        return full_file.replace(fixed_code.strip(), vulnerable_code.strip(), 1)
    return None


CUSTOM_QUERY = (
    "/mnt/ssd/aryawu/redteaming_code_auditors"
    "/attacker/codeql_queries/NullDerefInterproc.ql"
)


def _fetch_local_headers(src_text: str, repo_url: str,
                         commit: str, file_path: str,
                         tmp_dir: Path, token: str | None):
    """
    Fetch #include "..." headers from the same directory in the same commit
    and write them alongside the source file so CodeQL can parse types.
    Silently skips any header that can't be fetched.
    """
    file_dir = str(Path(file_path).parent)
    for m in re.finditer(r'#include\s+"([^"]+)"', src_text):
        header = m.group(1)
        # Resolve relative to the file's directory
        header_path = str(Path(file_dir) / header).lstrip("/")
        url = _github_raw_url(repo_url, commit, header_path)
        if not url:
            continue
        content = fetch_url(url, token)
        if content is None:
            continue
        dest = tmp_dir / header
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)


def codeql_fires(codeql: str, src: str, suffix: str,
                 repo_url: str = "", commit: str = "",
                 file_path: str = "", token: str | None = None) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        tmp    = Path(tmp)
        src_f  = tmp / f"target{suffix}"
        db_dir = tmp / "db"
        out_f  = tmp / "results.sarif"
        src_f.write_text(src)

        # Fetch local headers so CodeQL can resolve struct definitions
        if repo_url and commit:
            _fetch_local_headers(src, repo_url, commit, file_path, tmp, token)

        r = subprocess.run(
            [codeql, "database", "create", str(db_dir),
             "--language=cpp", f"--source-root={tmp}",
             "--build-mode=none", "--overwrite"],
            capture_output=True, timeout=120,
        )
        if r.returncode != 0:
            return False

        r = subprocess.run(
            [codeql, "database", "analyze", str(db_dir),
             CUSTOM_QUERY,
             "--format=sarif-latest", f"--output={out_f}"],
            capture_output=True, timeout=120,
        )
        if r.returncode != 0:
            return False

        sarif = json.loads(out_f.read_text())
        return any(run.get("results") for run in sarif.get("runs", []))


def run_filter4(in_path: str, out_dir: str, limit: int):
    codeql = find_codeql()
    if not codeql:
        print("ERROR: codeql binary not found. "
              "Install from https://github.com/github/codeql-action/releases")
        sys.exit(1)

    lines = Path(in_path).read_text().splitlines()
    total = len(lines)
    print(f"\nFilter 4 (CodeQL): {total} candidates from {in_path}")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    counts  = dict(hit=0, miss=0)
    written = 0

    for i, line in enumerate(lines):
        rec          = json.loads(line)
        fixed_file   = rec.get("full_file", "")
        # Restore the buggy function so CodeQL sees the NPD, not the fix
        buggy_file   = _make_buggy_file(
            fixed_file,
            rec.get("_fixed_code", ""),
            rec.get("vulnerable_code", ""),
        )
        suffix = Path(rec["file_path"]).suffix.lower() or ".c"
        tag    = f"[{i+1}/{total}]"

        print(f"  {tag} CodeQL on {rec['file_path']} …", end=" ", flush=True)
        if codeql_fires(codeql, buggy_file, suffix,
                        repo_url=rec.get("repo_url", ""),
                        commit=rec.get("commit_hash", ""),
                        file_path=rec["file_path"],
                        token=os.environ.get("GITHUB_TOKEN")):
            counts["hit"] += 1
            print("HIT")
            candidate = {k: v for k, v in rec.items() if not k.startswith("_")}
            candidate["full_file"] = buggy_file  # buggy state, not fixed
            slug = (f"{candidate['source']}_{candidate['cve_id']}_"
                    f"{Path(rec['file_path']).stem}")[:80].replace("/", "_")
            (Path(out_dir) / f"{slug}.json").write_text(
                json.dumps(candidate, indent=2))
            written += 1
        else:
            counts["miss"] += 1
            print("miss (blind spot, dropped)")

        if limit and written >= limit:
            print(f"  (stopped early at --limit {limit})")
            break

    print(f"\nFilter 4 complete:  hit={counts['hit']}  miss={counts['miss']}")
    print(f"{written} candidate.json files → {out_dir}/")


# ── Filter 5 (reasoning pointer coverage heuristic) ──────────────────────────

_PTR_NOISE = {
    "NULL", "null", "nullptr", "if", "else", "return", "sizeof", "while",
    "for", "do", "int", "void", "char", "long", "unsigned", "signed",
    "static", "struct", "const", "true", "false", "new", "delete",
    "this", "self", "err", "ret", "res", "rv",
}


def _extract_diff_pointers(added: list[str], removed: list[str]) -> set[str]:
    """Extract base pointer names from diff lines (both added and removed).

    Looks for:
      - foo->bar          → foo  (the pointer that may be NULL)
      - foo == NULL       → foo
      - NULL == foo       → foo
      - if (!foo)         → foo
      - if (foo == NULL)  → foo
    """
    ptrs: set[str] = set()
    for line in added + removed:
        # foo->bar → foo
        for m in re.finditer(r'\b(\w+)\s*->', line):
            ptrs.add(m.group(1))
        # foo == NULL  /  foo != NULL
        for m in re.finditer(r'\b(\w+)\s*(?:==|!=)\s*NULL\b', line):
            ptrs.add(m.group(1))
        # NULL == foo  /  NULL != foo
        for m in re.finditer(r'\bNULL\s*(?:==|!=)\s*(\w+)\b', line):
            ptrs.add(m.group(1))
        # if (!foo)  /  if (foo)  inside a null-guard context
        for m in re.finditer(r'if\s*\(\s*!?\s*(\w+)\s*\)', line):
            ptrs.add(m.group(1))
    # Remove noise words and very-short names that are likely loop vars
    return {p for p in ptrs if p not in _PTR_NOISE and len(p) >= 2}


def _reasoning_mentions(reasoning: str, ptr: str) -> bool:
    """True if ptr appears as a whole word in reasoning (case-insensitive)."""
    return bool(re.search(r'\b' + re.escape(ptr) + r'\b', reasoning, re.IGNORECASE))


def check_pointer_coverage(vuln_code: str, fixed_code: str,
                            reasoning: str) -> dict:
    """
    Heuristic: does the VulnLLM-R reasoning mention the pointer(s) that the
    patch actually touches?

    Returns a dict with:
      heuristic  — "match" | "mismatch" | "no_diff_ptrs"
      diff_ptrs  — list of pointers extracted from the diff
      mentioned  — subset of diff_ptrs found in the reasoning
      unmentioned — subset not found
    """
    import difflib
    a = (vuln_code  or "").splitlines()
    b = (fixed_code or "").splitlines()
    added, removed = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
        if tag in ("replace", "delete"):
            removed += a[i1:i2]
        if tag in ("replace", "insert"):
            added += b[j1:j2]

    diff_ptrs = _extract_diff_pointers(added, removed)
    if not diff_ptrs:
        return {
            "heuristic":   "no_diff_ptrs",
            "diff_ptrs":   [],
            "mentioned":   [],
            "unmentioned": [],
        }

    mentioned   = {p for p in diff_ptrs if _reasoning_mentions(reasoning, p)}
    unmentioned = diff_ptrs - mentioned
    verdict = "match" if mentioned else "mismatch"
    return {
        "heuristic":   verdict,
        "diff_ptrs":   sorted(diff_ptrs),
        "mentioned":   sorted(mentioned),
        "unmentioned": sorted(unmentioned),
    }


def run_filter5(in_path: str, results_path: str, out_path: str) -> None:
    """Annotate VulnLLM-R results with pointer coverage heuristic and write
    augmented JSONL.  Only 'vulnerable' entries are evaluated; 'safe' entries
    get heuristic='n/a'."""
    # Load source data keyed by (cve_id, func_name)
    src: dict[tuple, dict] = {}
    for line in Path(in_path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        src[(r.get("cve_id", ""), r.get("func_name", ""))] = r

    # Load results
    results: list[dict] = []
    for line in Path(results_path).read_text().splitlines():
        if not line.strip():
            continue
        results.append(json.loads(line))

    counts = {"match": 0, "mismatch": 0, "no_diff_ptrs": 0, "n/a": 0}
    out_lines = []

    for res in results:
        key = (res.get("cve_id", ""), res.get("func_name", ""))
        row = src.get(key)

        if res.get("verdict") != "vulnerable" or not row:
            ann = {"heuristic": "n/a", "diff_ptrs": [], "mentioned": [], "unmentioned": []}
        else:
            vuln  = row.get("vulnerable_code", "")
            fixed = row.get("_fixed_code") or row.get("fixed_code", "")
            reasoning = res.get("reasoning", "")
            ann = check_pointer_coverage(vuln, fixed, reasoning)

        counts[ann["heuristic"]] += 1
        out_lines.append(json.dumps({**res, **ann}))

    Path(out_path).write_text("\n".join(out_lines) + "\n")

    total_vuln = counts["match"] + counts["mismatch"] + counts["no_diff_ptrs"]
    print(f"\nFilter 5 (pointer coverage heuristic)")
    print(f"  Vulnerable entries evaluated : {total_vuln}")
    print(f"  match        (reasoning mentions diff pointer) : {counts['match']}")
    print(f"  mismatch     (reasoning ignores diff pointer)  : {counts['mismatch']}")
    print(f"  no_diff_ptrs (diff had no extractable pointers): {counts['no_diff_ptrs']}")
    print(f"  n/a          (safe / not evaluated)            : {counts['n/a']}")
    print(f"\nOutput → {out_path}")


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
                    help="Run filter 3 (GitHub fetch + compile)")
    ap.add_argument("--filter4",  action="store_true",
                    help="Run filter 4 (CodeQL)")
    ap.add_argument("--filter5",  action="store_true",
                    help="Run filter 5 (reasoning pointer coverage heuristic)")
    ap.add_argument("--in",  dest="in_path",  help="Input JSONL (filter3/filter4/filter5)")
    ap.add_argument("--results", dest="results_path",
                    help="VulnLLM-R results JSONL (filter5)")
    ap.add_argument("--out", dest="out_path", help="Output file or directory")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"),
                    help="GitHub token (default: $GITHUB_TOKEN)")
    ap.add_argument("--limit", type=int, default=0,
                    help="Stop after N survivors (for testing)")
    args = ap.parse_args()

    if args.probe:
        run_probe()
    elif args.filter12:
        if not args.out_path:
            ap.error("--filter12 requires --out")
        run_filter12(args.out_path, args.limit)
    elif args.filter3:
        if not args.in_path or not args.out_path:
            ap.error("--filter3 requires --in and --out")
        run_filter3(args.in_path, args.out_path, args.token, args.limit)
    elif args.filter4:
        if not args.in_path or not args.out_path:
            ap.error("--filter4 requires --in and --out")
        run_filter4(args.in_path, args.out_path, args.limit)
    elif args.filter5:
        if not args.in_path or not args.results_path or not args.out_path:
            ap.error("--filter5 requires --in, --results, and --out")
        run_filter5(args.in_path, args.results_path, args.out_path)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
