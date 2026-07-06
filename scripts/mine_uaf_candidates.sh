#!/usr/bin/env bash
# mine_uaf_candidates.sh — Task1 mining pipeline for CWE-416 (UAF), mirroring
# the NPD pipeline described in the paper: CWE/single-file/non-trivial-body
# filter -> fetch from GitHub -> clone + build + run the real test suite.
#
# All UAF outputs use a distinct _uaf suffix so they never collide with the
# existing NPD artifacts (cvebench/f3_nolimit_dedup_func.jsonl,
# cvebench/samples_cve_fix/, /tmp/cve_repos_fix).
#
# Usage:
#   bash scripts/mine_uaf_candidates.sh [--limit N]
#
# Stages (run in order; each writes/reads a fixed path below):
#   1. filter12    — stream MegaVul, keep CWE-416 + single-file + non-trivial body
#   2. filter3     — fetch full file from GitHub at the fix commit
#   3. assign-ids  — assign pilot_id (housekeeping; every later stage requires it)
#   4. testsuite   — clone each repo at the fix commit, build, run its test suite
#
# Deliberately NOT deduped here: MegaVul's raw stream repeats ~48% of rows
# (literal duplicates, not the same as one CVE legitimately touching several
# functions). Dedup on the *input* pool before running the attacker would
# throw away survivors — a "duplicate" row can independently pass or fail
# attacker generation + patch_and_test where its sibling doesn't. Run
# --dedup (see filter_pipeline.py) on the FINAL confirmed/passing set,
# after generate_attacker.py + patch_and_test.py, not here.
#
# Safe to re-run: filter3 supports --skip-existing (not wired here by
# default — pass --resume to enable), and check_repo_testsuite.py caches
# clones by repo slug.

set -euo pipefail
cd "$(dirname "$0")/.."

LIMIT_ARGS=()
RESUME=0
for arg in "$@"; do
  case "$arg" in
    --limit) shift ;;
    --resume) RESUME=1 ;;
  esac
done
if [[ "${1:-}" == "--limit" && -n "${2:-}" ]]; then
  LIMIT_ARGS=(--limit "$2")
fi

F12_OUT="cvebench/f12_uaf.jsonl"
F3_OUT="cvebench/f3_uaf.jsonl"
F3_IDS_OUT="cvebench/f3_uaf_ids.jsonl"
SAMPLES_DIR="cvebench/samples_cve_uaf"
CLONE_DIR="/tmp/cve_repos_uaf"
TESTSUITE_OUT="cvebench/results_testsuite_uaf.json"

echo "=== Stage 1: filter12 (CWE-416, single-file, non-trivial body) ==="
python3 cvebench/filter_pipeline.py --filter12 --cwe 416 --out "$F12_OUT" "${LIMIT_ARGS[@]}"

echo
echo "=== Stage 2: filter3 (fetch full file from GitHub) ==="
SKIP_FLAG=()
[[ "$RESUME" == "1" ]] && SKIP_FLAG=(--skip-existing)
python3 cvebench/filter_pipeline.py --filter3 --in "$F12_OUT" --out "$F3_OUT" "${SKIP_FLAG[@]}"

echo
echo "=== Stage 3: assign pilot_id ==="
python3 cvebench/filter_pipeline.py --assign-ids --cwe 416 --in "$F3_OUT" --out "$F3_IDS_OUT"

echo
echo "=== Stage 4: clone + build + test each surviving repo ==="
mkdir -p "$SAMPLES_DIR"
python3 cvebench/check_repo_testsuite.py "$F3_IDS_OUT" \
    --samples-dir "$SAMPLES_DIR" \
    --clone-dir "$CLONE_DIR" \
    --out "$TESTSUITE_OUT"

echo
echo "Done. Outputs:"
echo "  $F12_OUT"
echo "  $F3_OUT"
echo "  $F3_IDS_OUT"
echo "  $SAMPLES_DIR/  (per-sample repo_testsuite_pass/partial/fail/none sentinels)"
echo "  $TESTSUITE_OUT"
echo
echo "NOTE: dedup happens AFTER attacker generation + patch_and_test, on the"
echo "final confirmed set — see filter_pipeline.py --dedup. Not run here."
