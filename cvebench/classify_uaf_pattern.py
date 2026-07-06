#!/usr/bin/env python3
"""
classify_uaf_pattern.py — deterministic, high-precision-only mechanism hint
for CVE UAF candidates.

Reads a JSONL with vulnerable_code/_fixed_code (e.g. f3_uaf_ids.jsonl),
diffs the two, and tags each row with a mechanism hint IF AND ONLY IF the
signal is textually unambiguous. Writes an augmented JSONL (same rows,
plus uaf_mechanism_hint / uaf_mechanism_evidence, both empty string if
unclassified).

Only two mechanisms are detected — deliberately conservative:

  double_free       — the IDENTICAL (function, variable) free-call pair
                       appears 2+ times in vulnerable_code. High precision:
                       spot-checked 5/5 real double-frees on manual review.

  ownership_escape   — `.get()` (raw-pointer extraction from a smart
                        pointer) appears in vulnerable_code but not in
                        _fixed_code, i.e. the fix stops extracting the raw
                        alias. Verified against the real podofo CVE.

A third candidate signal — "sequential reuse" (free-shaped call on X,
then X used again later) — was tried and DROPPED: it cannot distinguish
a call that frees the WHOLE object from a call that only frees some
INTERNAL member and correctly returns the object still valid (e.g. curl's
Curl_up_free frees sub-state, not `data` itself — data is legitimately
reused afterward). That produced false positives on manual review and is
not shipped here. Do not re-add it without a way to tell those two cases
apart (e.g. inspecting the helper's own body, not just its name).

Usage:
  python3 cvebench/classify_uaf_pattern.py \\
      cvebench/f3_uaf_ids.jsonl \\
      --out cvebench/f3_uaf_ids.hinted.jsonl
"""

import argparse
import json
import re
from pathlib import Path

CALL_FREE = re.compile(r'\b(k?free|\w*_free|\w*_release|\w*_unref|vfree|dealloc|g_free)\s*\(\s*&?(\w+)\s*[,)]')
BARE_DELETE = re.compile(r'\bdelete(?:\[\])?\s+(\w+)\s*;')
GET_CALL = re.compile(r'\.get\(\)')


def _free_calls(code: str) -> list[tuple[str, str]]:
    calls = []
    for m in CALL_FREE.finditer(code):
        calls.append((m.group(1), m.group(2)))
    for m in BARE_DELETE.finditer(code):
        calls.append(("delete", m.group(1)))
    return calls


def classify(vulnerable_code: str, fixed_code: str) -> tuple[str, str]:
    """Return (mechanism, evidence) or ("", "") if no confident match."""
    if not vulnerable_code:
        return "", ""

    calls = _free_calls(vulnerable_code)

    # double_free: identical (fn, var) pair repeated.
    pair_counts: dict[tuple[str, str], int] = {}
    for fn, var in calls:
        pair_counts[(fn, var)] = pair_counts.get((fn, var), 0) + 1
    doubles = {k: v for k, v in pair_counts.items() if v >= 2}
    if doubles:
        (fn, var), n = next(iter(doubles.items()))
        return "double_free", f"'{fn}({var})' called {n} times in the original buggy function"

    # ownership_escape: .get() present in buggy, removed in fix.
    vuln_gets = len(GET_CALL.findall(vulnerable_code))
    fixed_gets = len(GET_CALL.findall(fixed_code)) if fixed_code else 0
    if vuln_gets > fixed_gets:
        return "ownership_escape", (
            "the original buggy function extracts a raw pointer via .get() "
            "from a smart pointer; the fix stops doing that"
        )

    return "", ""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("jsonl")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = [json.loads(l) for l in Path(args.jsonl).read_text().splitlines() if l.strip()]
    counts: dict[str, int] = {}
    with open(args.out, "w") as fout:
        for row in rows:
            mech, evidence = classify(row.get("vulnerable_code", ""), row.get("_fixed_code", ""))
            row["uaf_mechanism_hint"] = mech
            row["uaf_mechanism_evidence"] = evidence
            counts[mech or "unclassified"] = counts.get(mech or "unclassified", 0) + 1
            fout.write(json.dumps(row) + "\n")

    print(f"Classified {len(rows)} rows → {args.out}")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {k:<20} {v}")


if __name__ == "__main__":
    main()
