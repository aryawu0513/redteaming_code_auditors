#!/usr/bin/env bash
# phase1_gen_and_test.sh — Phase 1: can this model write a vulnerable-but-
# passing patch?
#
# Wraps the EXISTING, unmodified cvebench pipeline scripts:
#   cvebench/generate_attacker.py   — model fills in the NPD stub
#   cvebench/patch_and_test.py      — splice into a fresh clone, build, test
#
# Output is written to smaller_attacker/results/<tag>/phase1/rounds/r1/ — a
# "round" directory, one level deeper than a plain --output-dir would give —
# because cvebench/judge_cve_new.py and cvebench/build_benchmark.py (used by
# phase1_judge_and_build.sh) both expect a --rounds-dir containing named
# round subdirs (r1, r2, ...), not a flat directory. Keeping this layout
# from the start means Phase 1 output plugs directly into the judge/build
# step without any renaming.
#
# Reads inputs from cvebench/samples_cve_fix (untouched). Writes ONLY into
# smaller_attacker/results/<tag>/phase1/ — nothing in cvebench/ is modified.
#
# Usage:
#   bash smaller_attacker/phase1_gen_and_test.sh <tag> <hf_id> <port> [ids-file]
#
# Example (small pilot, default ids-file):
#   bash smaller_attacker/phase1_gen_and_test.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100
#
# Example (full 125-slug run):
#   bash smaller_attacker/phase1_gen_and_test.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100 \
#       smaller_attacker/slugs_full125.txt
#
# Requires the model already being served (see serve/serve_*.sh) at
# http://localhost:<port>/v1.

set -euo pipefail

TAG="${1:?usage: phase1_gen_and_test.sh <tag> <hf_id> <port> [ids-file]}"
MODEL="${2:?usage: phase1_gen_and_test.sh <tag> <hf_id> <port> [ids-file]}"
PORT="${3:?usage: phase1_gen_and_test.sh <tag> <hf_id> <port> [ids-file]}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IDS_FILE="${4:-$REPO_ROOT/smaller_attacker/pilot_slugs_phase1.txt}"
OUT_DIR="$REPO_ROOT/smaller_attacker/results/$TAG/phase1/rounds/r1"
SAMPLES_DIR="$REPO_ROOT/cvebench/samples_cve_fix"
JSONL="$REPO_ROOT/cvebench/f3_nolimit_dedup_func.slim.jsonl"
CLONE_DIR="/tmp/smaller_attacker_clone_scratch/$TAG"
BASE_URL="http://localhost:$PORT/v1"

mkdir -p "$OUT_DIR"

echo "=== Phase 1: $TAG ($MODEL) ==="
echo "Slug list: $IDS_FILE ($(grep -c . "$IDS_FILE") slugs)"
echo "Checking server at $BASE_URL ..."
curl -sf "$BASE_URL/models" > /dev/null || {
    echo "ERROR: no model server at $BASE_URL — start it first (see smaller_attacker/serve/)." >&2
    exit 1
}

echo "--- Step 1: generate attacker_output.cc for each sample ---"
python3 "$REPO_ROOT/cvebench/generate_attacker.py" \
    "$JSONL" \
    --ids-file    "$IDS_FILE" \
    --samples-dir "$SAMPLES_DIR" \
    --output-dir  "$OUT_DIR" \
    --model       "$MODEL" \
    --base-url    "$BASE_URL" \
    --workers     4

echo "--- Step 2: splice, build, run test suite ---"
python3 "$REPO_ROOT/cvebench/patch_and_test.py" \
    "$JSONL" \
    --ids-file    "$IDS_FILE" \
    --samples-dir "$SAMPLES_DIR" \
    --output-dir  "$OUT_DIR" \
    --clone-dir   "$CLONE_DIR"

echo "Phase 1 done for $TAG. Results in $OUT_DIR/attacker_results.json"
echo "Next: bash smaller_attacker/phase1_judge_and_build.sh $TAG \"$IDS_FILE\""
