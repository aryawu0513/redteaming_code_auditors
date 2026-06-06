#!/usr/bin/env python3
"""
Probe colin/PrimeVul to determine if the MegaVul CVE mining pipeline
(filter_pipeline.py) can be applied to it, and how many entries survive
the equivalent of Filter 1+2.

Compares candidate counts against the MegaVul baseline:
  MegaVul: ~51k CWE-476 C/C++ → 2,261 after Filter 1+2 → 275 after dedup → 185 VulnLLM-R+

Usage:
    python scripts/oneoff/probe_primevul.py [--limit N]
    python scripts/oneoff/probe_primevul.py --probe   # just print schema of first 3 rows

Requires: pip install datasets
"""

import argparse
import json
import re
import sys
from pathlib import Path

HF_DATASET = "colin/PrimeVul"
C_LANGS    = {"C", "C++", "c", "c++"}
C_EXTS     = {".c", ".cc", ".cpp", ".cxx"}
HEADER_EXTS = {".h", ".hpp", ".hh", ".hxx"}


# ── Field helpers ─────────────────────────────────────────────────────────────

def is_npd(row) -> bool:
    cwe = row.get("cwe_id") or row.get("cwe") or row.get("CWE") or ""
    if isinstance(cwe, list):
        return any("476" in str(x) for x in cwe)
    return "476" in str(cwe)


def get_lang(row) -> str:
    return (row.get("language") or row.get("lang") or "").strip()


def get_file_path(row) -> str:
    # PrimeVul may store a single path as a string or as a list
    fp = row.get("file_path") or row.get("file_name") or row.get("filepath") or ""
    if isinstance(fp, list):
        return fp[0] if fp else ""
    return str(fp)


def get_file_paths(row) -> list[str]:
    # Try known list-of-paths fields
    for key in ("file_paths", "files_changed", "changed_files"):
        val = row.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            return val
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
            return [val] if val else []
    # Fall back to single path
    fp = get_file_path(row)
    return [fp] if fp else []


def is_c_cpp(row) -> bool:
    lang = get_lang(row)
    if lang in C_LANGS:
        return True
    fps = get_file_paths(row)
    if fps:
        ext = Path(fps[0]).suffix.lower()
        return ext in C_EXTS
    fp = get_file_path(row)
    return Path(fp).suffix.lower() in C_EXTS if fp else False


def get_vuln_code(row) -> str:
    for key in ("vulnerable_code", "vuln_code", "func_before", "function_before",
                "before_func", "vul_func_with_fix", "source_before", "code_before"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


def get_fixed_code(row) -> str:
    for key in ("fixed_code", "fix_code", "func_after", "function_after",
                "after_func", "source_after", "code_after"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


def get_repo_url(row) -> str:
    for key in ("repo_url", "repository_url", "commit_url", "url", "repo"):
        v = row.get(key)
        if v and "github.com" in str(v):
            return str(v)
    return ""


def has_github_url(row) -> bool:
    return bool(get_repo_url(row))


def has_commit_hash(row) -> bool:
    for key in ("commit_hash", "commit_id", "fix_commit", "hash"):
        if row.get(key):
            return True
    # Try to extract from commit URL
    url = get_repo_url(row)
    return bool(re.search(r"/commit/[0-9a-f]{7,}", url))


def count_body_statements(code: str) -> int:
    """Identical to filter_pipeline.py version."""
    lines = code.strip().splitlines()
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


# ── Probe ─────────────────────────────────────────────────────────────────────

def run_probe():
    from datasets import load_dataset
    print(f"Probing {HF_DATASET} — schema of first 3 rows:")
    try:
        ds = load_dataset(HF_DATASET, split="train", streaming=True)
    except Exception:
        ds = load_dataset(HF_DATASET, streaming=True)
        ds = ds[list(ds.keys())[0]]

    for i, row in enumerate(ds):
        print(f"\n── Row {i} keys ──")
        for k, v in row.items():
            if isinstance(v, str):
                preview = repr(v[:300])
            else:
                preview = repr(v)[:200]
            print(f"  {k:<35} {preview}")
        if i >= 2:
            break


# ── Filter 1+2 equivalent ─────────────────────────────────────────────────────

def run_filter12(limit: int):
    from datasets import load_dataset

    print(f"Loading {HF_DATASET} (streaming) …")

    # PrimeVul may have multiple splits
    try:
        ds_info = load_dataset(HF_DATASET)
        splits = list(ds_info.keys())
        print(f"  Available splits: {splits}")
    except Exception as e:
        print(f"  (Could not load all splits: {e})")
        splits = ["train"]

    all_counts = {}

    for split in splits:
        print(f"\n{'='*60}")
        print(f"Split: {split}")
        print(f"{'='*60}")
        try:
            ds = load_dataset(HF_DATASET, split=split, streaming=True)
        except Exception as e:
            print(f"  Skipping split '{split}': {e}")
            continue

        counts = dict(
            total=0, npd=0, c_cpp=0,
            has_vuln_code=0, has_fixed_code=0,
            has_github_url=0, has_commit=0,
            f1_pass=0, f1_skip_multi=0, f1_skip_none=0,
            f2_pass=0, f2_skip_trivial=0,
            f2_no_fixed=0,
        )
        survivors = []

        for row in ds:
            counts["total"] += 1

            if not is_npd(row):
                continue
            counts["npd"] += 1

            if not is_c_cpp(row):
                continue
            counts["c_cpp"] += 1

            vuln_code  = get_vuln_code(row)
            fixed_code = get_fixed_code(row)

            if vuln_code:
                counts["has_vuln_code"] += 1
            else:
                continue  # same gate as MegaVul

            if fixed_code:
                counts["has_fixed_code"] += 1

            if has_github_url(row):
                counts["has_github_url"] += 1

            if has_commit_hash(row):
                counts["has_commit"] += 1

            # Filter 1: single-file touch
            fps = get_file_paths(row)
            if not fps:
                counts["f1_skip_none"] += 1
                continue
            if len(fps) > 1:
                counts["f1_skip_multi"] += 1
                continue
            counts["f1_pass"] += 1

            # Filter 2: non-trivial function bodies
            body_vuln  = count_body_statements(vuln_code)
            body_fixed = count_body_statements(fixed_code) if fixed_code else 0

            if fixed_code and body_fixed < 2:
                counts["f2_skip_trivial"] += 1
                continue
            if not fixed_code:
                counts["f2_no_fixed"] += 1
                # Still count it — maybe PrimeVul lacks fixed_code for all entries
            if body_vuln < 2:
                counts["f2_skip_trivial"] += 1
                continue

            counts["f2_pass"] += 1
            survivors.append(row)

            if counts["total"] % 5000 == 0:
                print(f"  … {counts['total']} rows | npd={counts['npd']} "
                      f"c/cpp={counts['c_cpp']} f1={counts['f1_pass']} "
                      f"f2={counts['f2_pass']}")

            if limit and counts["f2_pass"] >= limit:
                print(f"  (stopped early at --limit {limit})")
                break

        # Print results for this split
        print(f"\nResults for split '{split}':")
        print(f"  {'Total rows':<40} {counts['total']:>6}")
        print(f"  {'CWE-476 (NPD)':<40} {counts['npd']:>6}")
        print(f"  {'C/C++':<40} {counts['c_cpp']:>6}")
        print(f"  {'has vulnerable_code':<40} {counts['has_vuln_code']:>6}")
        print(f"  {'has fixed_code':<40} {counts['has_fixed_code']:>6}")
        print(f"  {'has GitHub URL':<40} {counts['has_github_url']:>6}  ← needed for Filter 3")
        print(f"  {'has commit hash':<40} {counts['has_commit']:>6}  ← needed for Filter 3")
        print(f"  {'→ F1 pass (single file touch)':<40} {counts['f1_pass']:>6}  "
              f"(skip: {counts['f1_skip_none']} no-file, {counts['f1_skip_multi']} multi-file)")
        print(f"  {'→ F2 pass (body ≥ 2 stmts)':<40} {counts['f2_pass']:>6}  "
              f"(skip: {counts['f2_skip_trivial']} trivial, {counts['f2_no_fixed']} missing fixed)")

        all_counts[split] = counts

        # Show a representative survivor to inspect fields
        if survivors:
            print(f"\nSample survivor (first entry that passed F1+F2):")
            row = survivors[0]
            interesting = [
                "cve_id", "cwe_id", "cwe", "CWE",
                "language", "lang",
                "file_path", "file_paths", "file_name",
                "repo_url", "repository_url", "commit_url",
                "commit_hash", "commit_id", "fix_commit",
            ]
            for k in interesting:
                if k in row:
                    v = row[k]
                    print(f"    {k:<30} {repr(str(v)[:150])}")
            # Show which vuln/fixed keys are present
            for k in ("vulnerable_code", "vuln_code", "func_before", "function_before",
                      "vul_func_with_fix",
                      "fixed_code", "fix_code", "func_after", "function_after"):
                if k in row and row[k]:
                    print(f"    {k:<30} <present, {len(str(row[k]))} chars>")

    # Cross-split summary
    if len(all_counts) > 1:
        print(f"\n{'='*60}")
        print("CROSS-SPLIT SUMMARY")
        print(f"{'='*60}")
        total_f2 = sum(c["f2_pass"] for c in all_counts.values())
        total_rows = sum(c["total"] for c in all_counts.values())
        print(f"  Total rows across all splits : {total_rows}")
        print(f"  Total F1+F2 survivors        : {total_f2}")

    # Comparison with MegaVul
    print(f"\n{'='*60}")
    print("COMPARISON WITH MEGAVUL")
    print(f"{'='*60}")
    print(f"  MegaVul raw CWE-476 C/C++   : ~51,000")
    print(f"  MegaVul F1+F2 survivors     :   2,261")
    print(f"  MegaVul after GitHub fetch  :     987")
    print(f"  MegaVul after dedup         :     275")
    print(f"  MegaVul VulnLLM-R positives :     185")
    print(f"  MegaVul final (F5 filtered) :     101")
    print()
    for split, counts in all_counts.items():
        f2 = counts["f2_pass"]
        ratio = f2 / max(counts["total"], 1) * 100
        print(f"  PrimeVul [{split}] F1+F2 survivors : {f2:>5}  ({ratio:.1f}% of total)")
        can_fetch = counts["has_github_url"] and counts["has_commit"]
        if can_fetch:
            print(f"    → Filter 3 (GitHub fetch) is FEASIBLE — has repo URL + commit hash")
        else:
            missing = []
            if not counts["has_github_url"]:
                missing.append("GitHub URL")
            if not counts["has_commit"]:
                missing.append("commit hash")
            print(f"    → Filter 3 BLOCKED — missing: {', '.join(missing)}")
            print(f"    → However, if PrimeVul includes full file text, Filter 3 may be skippable")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probe",  action="store_true",
                    help="Print first 3 rows and exit (schema inspection)")
    ap.add_argument("--limit", type=int, default=0,
                    help="Stop after N F2 survivors per split (for quick testing)")
    args = ap.parse_args()

    if args.probe:
        run_probe()
    else:
        run_filter12(args.limit)


if __name__ == "__main__":
    main()
