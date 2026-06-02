#!/usr/bin/env python3
"""
Count how many usable CWE-476 (NPD) C/C++ entries we can get from
MegaVul and CVEFixes, streamed from HuggingFace. No downloads needed.

Both datasets have the same structure for our purposes:
  - cwe_id / cwe_ids   : filter to CWE-476
  - language           : filter to C / C++
  - vulnerable_code    : the buggy function (MegaVul) or full file (CVEFixes)
  - commit_message     : context for task.md generation
  - repo_url + hash + file_path : to pull full file from GitHub

Usage:
    python3 count_npd_sources.py --megavul
    python3 count_npd_sources.py --cvefixes
    python3 count_npd_sources.py --megavul --cvefixes

Requires:
    pip install datasets
"""

import argparse
from collections import Counter


C_LANGS = {"C", "C++"}


def stream_count(dataset_id: str, cwe_field: str, lang_field: str, lang_values: set):
    from datasets import load_dataset

    print(f"\n{'='*50}")
    print(f"{dataset_id} (streaming)")
    print(f"{'='*50}")

    ds = load_dataset(dataset_id, split="train", streaming=True)

    total          = 0
    npd            = 0
    c_cpp          = 0
    has_vuln_code  = 0
    has_commit_msg = 0
    has_coords     = 0  # repo_url + hash + file_path all present
    under_200      = 0
    repo_counts    = Counter()

    for row in ds:
        total += 1

        # CWE filter — MegaVul uses cwe_ids (list), CVEFixes uses cwe_id (string)
        cwe = row.get(cwe_field)
        if isinstance(cwe, list):
            is_npd = "CWE-476" in cwe
        else:
            is_npd = cwe == "CWE-476"
        if not is_npd:
            continue
        npd += 1

        if row.get(lang_field) not in lang_values:
            continue
        c_cpp += 1

        vuln = (row.get("vulnerable_code") or "").strip()
        if not vuln:
            continue
        has_vuln_code += 1

        if row.get("commit_message") or row.get("commit_msg"):
            has_commit_msg += 1

        # Need all three coords to pull full file from GitHub
        has_all = (
            row.get("repo_url")
            and row.get("hash") or row.get("commit_hash")
            and row.get("file_paths") or row.get("file_path")
        )
        if has_all:
            has_coords += 1

        if len(vuln.splitlines()) <= 200:
            under_200 += 1

        repo_counts[row.get("repo_url", "unknown")] += 1

        if total % 1000 == 0:
            print(f"  ... scanned {total} rows, {npd} CWE-476, {c_cpp} C/C++")

    print(f"\nTotal rows scanned:          {total}")
    print(f"CWE-476:                     {npd}")
    print(f"C/C++:                       {c_cpp}")
    print(f"Has vulnerable_code:         {has_vuln_code}")
    print(f"Has commit message:          {has_commit_msg}/{has_vuln_code}")
    print(f"Has repo+hash+filepath:      {has_coords}/{has_vuln_code}")
    print(f"vulnerable_code <= 200 lines: {under_200}/{has_vuln_code}")

    print(f"\nTop 10 repos (of {len(repo_counts)} total):")
    for repo, count in repo_counts.most_common(10):
        print(f"  {count:4d}  {repo}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--megavul",  action="store_true",
                        help="Stream MegaVul from hitoshura25/megavul")
    parser.add_argument("--cvefixes", action="store_true",
                        help="Stream CVEFixes from hitoshura25/cvefixes")
    args = parser.parse_args()

    if not args.megavul and not args.cvefixes:
        parser.error("Provide at least one of --megavul or --cvefixes")

    try:
        import datasets  # noqa
    except ImportError:
        print("ERROR: pip install datasets")
        return

    if args.megavul:
        # MegaVul: cwe_ids is a list, language field is "language"
        stream_count(
            dataset_id  = "hitoshura25/megavul",
            cwe_field   = "cwe_id",   # single string in this HF version
            lang_field  = "language",
            lang_values = C_LANGS,
        )

    if args.cvefixes:
        # CVEFixes: cwe_id is a single string, language field is "language"
        stream_count(
            dataset_id  = "hitoshura25/cvefixes",
            cwe_field   = "cwe_id",
            lang_field  = "language",
            lang_values = C_LANGS,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()