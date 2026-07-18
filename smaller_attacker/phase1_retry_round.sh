#!/usr/bin/env bash
# phase1_retry_round.sh — round r2 (or later): retry only the slugs that
# didn't reach verdict=pass in the previous round, feeding back the build/
# test error message.
#
# Wraps the EXISTING, unmodified cvebench pipeline scripts, using the flags
# they already support for exactly this: generate_attacker.py's
# --with-error/--prev-output-dir append the previous round's error_output
# as feedback, and this IS the pipeline's own default methodology —
# build_benchmark.py's --only-rounds defaults to ["r1", "r2"].
#
# Usage:
#   bash smaller_attacker/phase1_retry_round.sh <tag> <hf_id> <port> \
#       <prev-round> <new-round> [ids-file]
#
# Example (r1 -> r2, full 125-slug run):
#   bash smaller_attacker/phase1_retry_round.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100 \
#       r1 r2 smaller_attacker/slugs_full125.txt

set -euo pipefail

TAG="${1:?usage: phase1_retry_round.sh <tag> <hf_id> <port> <prev-round> <new-round> [ids-file]}"
MODEL="${2:?usage: phase1_retry_round.sh <tag> <hf_id> <port> <prev-round> <new-round> [ids-file]}"
PORT="${3:?usage: phase1_retry_round.sh <tag> <hf_id> <port> <prev-round> <new-round> [ids-file]}"
PREV_ROUND="${4:?usage: phase1_retry_round.sh <tag> <hf_id> <port> <prev-round> <new-round> [ids-file]}"
NEW_ROUND="${5:?usage: phase1_retry_round.sh <tag> <hf_id> <port> <prev-round> <new-round> [ids-file]}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FULL_IDS_FILE="${6:-$REPO_ROOT/smaller_attacker/pilot_slugs_phase1.txt}"

ROUNDS_DIR="$REPO_ROOT/smaller_attacker/results/$TAG/phase1/rounds"
PREV_DIR="$ROUNDS_DIR/$PREV_ROUND"
NEW_DIR="$ROUNDS_DIR/$NEW_ROUND"
SAMPLES_DIR="$REPO_ROOT/cvebench/samples_cve_fix"
JSONL="$REPO_ROOT/cvebench/f3_nolimit_dedup_func.slim.jsonl"
CLONE_DIR="/tmp/smaller_attacker_clone_scratch/$TAG"
BASE_URL="http://localhost:$PORT/v1"

if [ ! -f "$PREV_DIR/attacker_results.json" ]; then
    echo "ERROR: $PREV_DIR/attacker_results.json not found — run phase1_gen_and_test.sh (round $PREV_ROUND) first." >&2
    exit 1
fi

# Retry only the slugs that didn't reach verdict=pass in the previous round,
# restricted to the slug set this run cares about (FULL_IDS_FILE).
RETRY_IDS_FILE="$REPO_ROOT/smaller_attacker/results/$TAG/phase1/retry_ids_${PREV_ROUND}_to_${NEW_ROUND}.txt"
python3 -c "
import json
from pathlib import Path
results = json.loads(Path('$PREV_DIR/attacker_results.json').read_text())
full_ids = set(l.strip() for l in Path('$FULL_IDS_FILE').read_text().splitlines() if l.strip())
failed = [r['pid'] for r in results if r.get('verdict') != 'pass' and r['pid'] in full_ids]
Path('$RETRY_IDS_FILE').write_text('\n'.join(sorted(failed)) + ('\n' if failed else ''))
print(f'{len(failed)} slugs eligible for retry -> $RETRY_IDS_FILE')
"

mkdir -p "$NEW_DIR"

echo "=== Phase 1 retry: $TAG, round $PREV_ROUND -> $NEW_ROUND ==="
echo "Checking server at $BASE_URL ..."
curl -sf "$BASE_URL/models" > /dev/null || {
    echo "ERROR: no model server at $BASE_URL — start it first (see smaller_attacker/serve/)." >&2
    exit 1
}

echo "--- Step 1: regenerate with error feedback ---"
python3 "$REPO_ROOT/cvebench/generate_attacker.py" \
    "$JSONL" \
    --ids-file        "$RETRY_IDS_FILE" \
    --samples-dir     "$SAMPLES_DIR" \
    --output-dir      "$NEW_DIR" \
    --prev-output-dir "$PREV_DIR" \
    --with-error \
    --model           "$MODEL" \
    --base-url        "$BASE_URL" \
    --workers          4

echo "--- Step 2: splice, build, run test suite ---"
python3 "$REPO_ROOT/cvebench/patch_and_test.py" \
    "$JSONL" \
    --ids-file    "$RETRY_IDS_FILE" \
    --samples-dir "$SAMPLES_DIR" \
    --output-dir  "$NEW_DIR" \
    --clone-dir   "$CLONE_DIR"

echo "Round $NEW_ROUND done for $TAG. Results in $NEW_DIR/attacker_results.json"
echo "Next: bash smaller_attacker/phase1_judge_and_build.sh $TAG \"$FULL_IDS_FILE\" \"$PREV_ROUND $NEW_ROUND\""
