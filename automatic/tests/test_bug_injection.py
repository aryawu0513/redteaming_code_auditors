#!/usr/bin/env python3
"""
test_bug_injection.py — Verify RemoveNPDCheckAndExtractMetadata in isolation.

For each variant:
  1. Feed the safe version (RepoAudit/benchmark/{lang}/NPD/safe/{v}/{v}_clean.{ext}) to the predictor
  2. Diff buggy_code output against the existing benchmark file
  3. Compare extracted metadata fields against ground-truth from automatic/texts/{lang}_npd.json
     (only checks fields present in the ground-truth; Python GT predates caller_sig/last_line)

No attack-payload generation — Step 1 only.

Usage (from repo root, RepoAudit venv active):
    python automatic/test_bug_injection.py                        # all C variants
    python automatic/test_bug_injection.py --python               # all Python variants
    python automatic/test_bug_injection.py --demo                 # demo target repos
    python automatic/test_bug_injection.py --all                  # everything
    python automatic/test_bug_injection.py --variants findrec     # specific C variant
"""

import argparse
import difflib
import json
import os
import sys

import dspy

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from automatic.generate_variant import RemoveNPDCheckAndExtractMetadata

# ── C benchmark ───────────────────────────────────────────────────────────────
C_SAFE_DIR      = os.path.join(REPO, "RepoAudit", "benchmark", "C", "NPD", "safe")
C_BENCHMARK_DIR = os.path.join(REPO, "RepoAudit", "benchmark", "C", "NPD", "buggy")
C_TEXTS_PATH    = os.path.join(REPO, "automatic", "texts", "c_npd.json")
C_VARIANTS      = ["findrec", "creatend", "mkbuf", "allocate"]

# ── Python benchmark ──────────────────────────────────────────────────────────
PY_SAFE_DIR      = os.path.join(REPO, "RepoAudit", "benchmark", "Python", "NPD", "safe")
PY_BENCHMARK_DIR = os.path.join(REPO, "RepoAudit", "benchmark", "Python", "NPD", "buggy")
PY_TEXTS_PATH    = os.path.join(REPO, "automatic", "texts", "python_npd.json")
PY_VARIANTS      = ["finduser", "makeconn", "parseitem", "loadconf"]

# ── Demo repos ────────────────────────────────────────────────────────────────
# (label, safe_file, buggy_file, texts_json, language)
DEMO_CASES = [
    (
        "target_repo/users.c",
        os.path.join(REPO, "demo", "target_repo_orig", "users.c"),
        os.path.join(REPO, "demo", "target_repo",      "users.c"),
        os.path.join(REPO, "demo", "texts",            "demo.json"),
        "C",
    ),
    (
        "target_repo_v2/writer.c",
        os.path.join(REPO, "demo", "target_repo_v2_orig", "writer.c"),
        os.path.join(REPO, "demo", "target_repo_v2",      "writer.c"),
        os.path.join(REPO, "demo", "texts",               "demo_v2.json"),
        "C",
    ),
]

# All possible metadata fields; only those present in gt_meta are checked
ALL_META_FIELDS = ["callee", "caller", "var", "caller_sig", "call_line", "deref_line", "last_line"]


def unified_diff(a: str, b: str, label_a: str, label_b: str) -> str:
    return "".join(difflib.unified_diff(
        a.splitlines(keepends=True),
        b.splitlines(keepends=True),
        fromfile=label_a,
        tofile=label_b,
    ))


def test_case(label: str, safe_path: str, buggy_path: str, gt_meta: dict,
              language: str, predictor) -> bool:
    if not os.path.exists(safe_path):
        print(f"[{label}] SKIP — safe file not found: {safe_path}")
        return False
    if not os.path.exists(buggy_path):
        print(f"[{label}] SKIP — buggy file not found: {buggy_path}")
        return False

    with open(safe_path) as f:
        safe_code = f.read()
    with open(buggy_path) as f:
        expected_buggy = f.read()

    print(f"\n{'='*60}")
    print(f"[{label}] Running RemoveNPDCheckAndExtractMetadata (language={language})...")

    result = predictor(clean_c=safe_code, language=language)

    ok = True

    # ── 1. Diff buggy_code vs benchmark ──────────────────────────────────────
    diff = unified_diff(
        result.buggy_code.rstrip("\n") + "\n",
        expected_buggy.rstrip("\n") + "\n",
        label_a="agent output",
        label_b="expected buggy",
    )
    if diff:
        print(f"[{label}] BUGGY CODE diff (agent vs expected):")
        print(diff)
        ok = False
    else:
        print(f"[{label}] buggy_code: EXACT MATCH ✓")

    # ── 2. Compare metadata fields present in ground truth ───────────────────
    fields_to_check = [f for f in ALL_META_FIELDS if f in gt_meta]
    meta_ok = True
    for field in fields_to_check:
        agent_val = getattr(result, field, "").strip()
        expected  = gt_meta[field].strip()
        if agent_val == expected:
            print(f"[{label}] {field}: match ✓")
        else:
            print(f"[{label}] {field}: MISMATCH")
            print(f"          expected : {repr(expected)}")
            print(f"          got      : {repr(agent_val)}")
            meta_ok = False
            ok = False

    if meta_ok:
        print(f"[{label}] all {len(fields_to_check)} metadata fields match ✓")

    return ok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variants", nargs="+", default=C_VARIANTS,
                        choices=C_VARIANTS, metavar="VARIANT",
                        help="C benchmark variants to test (default: all 4)")
    parser.add_argument("--python", action="store_true",
                        help="Test Python benchmark variants")
    parser.add_argument("--demo",   action="store_true",
                        help="Test demo target repos")
    parser.add_argument("--all",    action="store_true",
                        help="Test C benchmark + Python benchmark + demo repos")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    lm = dspy.LM("anthropic/claude-sonnet-4-6", api_key=api_key)
    dspy.configure(lm=lm)
    predictor = dspy.ChainOfThought(RemoveNPDCheckAndExtractMetadata)

    results = {}

    # C benchmark variants
    if args.all or not (args.python or args.demo):
        with open(C_TEXTS_PATH) as f:
            c_gt = json.load(f)
        for v in args.variants:
            safe_path  = os.path.join(C_SAFE_DIR, v, f"{v}_clean.c")
            buggy_path = os.path.join(C_BENCHMARK_DIR, v, f"{v}_clean.c")
            gt_meta    = c_gt.get(v, {}).get("meta", {})
            results[v] = test_case(v, safe_path, buggy_path, gt_meta, "C", predictor)

    # Python benchmark variants
    if args.all or args.python:
        with open(PY_TEXTS_PATH) as f:
            py_gt = json.load(f)
        for v in PY_VARIANTS:
            safe_path  = os.path.join(PY_SAFE_DIR, v, f"{v}_clean.py")
            buggy_path = os.path.join(PY_BENCHMARK_DIR, v, f"{v}_clean.py")
            gt_meta    = py_gt.get(v, {}).get("meta", {})
            results[f"py/{v}"] = test_case(f"py/{v}", safe_path, buggy_path, gt_meta, "Python", predictor)

    # Demo repos
    if args.all or args.demo:
        for label, safe_path, buggy_path, texts_path, lang in DEMO_CASES:
            with open(texts_path) as f:
                gt_meta = json.load(f).get("meta", {})
            results[label] = test_case(label, safe_path, buggy_path, gt_meta, lang, predictor)

    print(f"\n{'='*60}")
    print("SUMMARY")
    passed = sum(results.values())
    for v, ok in results.items():
        print(f"  {v}: {'PASS' if ok else 'FAIL'}")
    print(f"\n{passed}/{len(results)} variants passed")


if __name__ == "__main__":
    main()
