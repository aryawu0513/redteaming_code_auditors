#!/bin/bash
# Rebuild CVE benchmark with the new tree-sitter + LLM portability pipeline.
# Writes to samples_cve_ts/ (NOT samples_cve/) to preserve the old build.
#
# Steps:
#   1. build_harness_cve.py  — tree-sitter extraction → LLM portability pass
#                               → reference.cc, auxiliary.cc, context.cc, starter.cc
#   2. generate_task_cve.py  — regenerate task.md + tests.cc from new context.cc
#   3. run_static_analysis_cve.py  — Clang/cppcheck/CodeQL/Infer on context.cc
#
# Usage:
#   bash scripts/oneoff/rebuild_cve_bench.sh [NPD-CVE-01 ...]
#
# Env vars:
#   OPENAI_API_KEY  (required)
#   GITHUB_TOKEN    (optional, but strongly recommended to avoid rate limiting)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MINING="$REPO_ROOT/repo_cve_dataset_mining"
JSONL="$MINING/pilot10.jsonl"
# Write to a NEW directory — never overwrite samples_cve (the old build)
SAMPLES="$MINING/samples_cve_ts"

# IDs to process (all 10 if none specified)
IDS=("${@}")
if [ ${#IDS[@]} -eq 0 ]; then
    IDS=(NPD-CVE-01 NPD-CVE-02 NPD-CVE-03 NPD-CVE-04 NPD-CVE-05
         NPD-CVE-06 NPD-CVE-07 NPD-CVE-08 NPD-CVE-09 NPD-CVE-10)
fi
IDS_STR="${IDS[*]}"

echo "=========================================================="
echo " CVE bench rebuild: ${#IDS[@]} samples"
echo " GITHUB_TOKEN: ${GITHUB_TOKEN:+(set)}"
echo "=========================================================="
echo ""

# ── Step 1: tree-sitter + LLM portability pass ─────────────────────────────
echo "=== STEP 1: build_harness_cve.py (tree-sitter + portability) ==="
python3 "$MINING/build_harness_cve.py" \
    "$JSONL" \
    $IDS_STR \
    --samples-dir "$SAMPLES"

echo ""

# ── Step 2: regenerate task.md + tests.cc ──────────────────────────────────
echo "=== STEP 2: generate_task_cve.py (task.md + tests.cc) ==="
python3 "$MINING/generate_task_cve.py" \
    "$JSONL" \
    $IDS_STR \
    --samples-dir "$SAMPLES" \
    --force

echo ""

# ── Step 3: static analysis on new context.cc ──────────────────────────────
echo "=== STEP 3: run_static_analysis_cve.py (Clang/cppcheck/CodeQL/Infer) ==="
python3 "$MINING/run_static_analysis_cve.py" \
    $IDS_STR \
    --samples-dir "$SAMPLES"

echo ""
echo "Done. New build is in samples_cve_ts/<pid>/."
echo "Original samples_cve/<pid>/ is untouched — diff freely:"
echo "  diff samples_cve/NPD-CVE-01/context.cc samples_cve_ts/NPD-CVE-01/context.cc"
