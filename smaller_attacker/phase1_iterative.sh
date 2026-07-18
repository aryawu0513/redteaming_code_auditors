#!/usr/bin/env bash
# phase1_iterative.sh — generate -> build/test -> judge -> pull out
# successes -> retry only what's left, for up to N rounds.
#
# Each round only judges ITS OWN newly-generated samples (judge_cve_new.py
# --rounds <this-round-only>) — no rescanning older rounds, no relying on
# judge_cve_new.py's cross-round "best" picking. A slug is permanently
# "good" (build+test pass AND judge=vulnerable) the moment it clears both
# gates in some round; it is then removed from the retry pool for all
# subsequent rounds. Only slugs still outstanding get regenerated (with
# --with-error feedback from their own previous attempt) each round.
#
# Wraps the EXISTING, unmodified cvebench scripts throughout:
#   cvebench/generate_attacker.py, cvebench/patch_and_test.py,
#   cvebench/judge_cve_new.py, cvebench/build_benchmark.py
# plus smaller_attacker/filter_judge.py (this repo's own cross-check glue).
# Writes ONLY into smaller_attacker/results/<tag>/.
#
# Usage:
#   bash smaller_attacker/phase1_iterative.sh <tag> <hf_id> <port> <full-ids-file> \
#       [max-rounds=5] [target-good=50]
#
# Example:
#   bash smaller_attacker/phase1_iterative.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100 \
#       smaller_attacker/slugs_full125.txt 5 50
#
# Requires: model server up (serve/serve_*.sh), OPENAI_API_KEY set (real
# OpenAI API, gpt-5-mini judge — OPENAI_BASE_URL is explicitly unset for
# judge calls so it can't be redirected to the local model server).

set -euo pipefail

TAG="${1:?usage: phase1_iterative.sh <tag> <hf_id> <port> <full-ids-file> [max-rounds] [target-good]}"
MODEL="${2:?usage: phase1_iterative.sh <tag> <hf_id> <port> <full-ids-file> [max-rounds] [target-good]}"
PORT="${3:?usage: phase1_iterative.sh <tag> <hf_id> <port> <full-ids-file> [max-rounds] [target-good]}"
FULL_IDS_FILE="${4:?usage: phase1_iterative.sh <tag> <hf_id> <port> <full-ids-file> [max-rounds] [target-good]}"
MAX_ROUNDS="${5:-5}"
TARGET_GOOD="${6:-50}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PHASE1_DIR="$REPO_ROOT/smaller_attacker/results/$TAG/phase1"
ROUNDS_DIR="$PHASE1_DIR/rounds"
SAMPLES_DIR="$REPO_ROOT/cvebench/samples_cve_fix"
JSONL="$REPO_ROOT/cvebench/f3_nolimit_dedup_func.slim.jsonl"
CLONE_DIR="/tmp/smaller_attacker_clone_scratch/$TAG"
BASE_URL="http://localhost:$PORT/v1"

CUMULATIVE_GOOD_SLUGS="$PHASE1_DIR/good_slugs.txt"
CUMULATIVE_GOOD_JUDGE="$PHASE1_DIR/judge_filtered.jsonl"
mkdir -p "$PHASE1_DIR"
touch "$CUMULATIVE_GOOD_SLUGS" "$CUMULATIVE_GOOD_JUDGE"

# Resume support: if good_slugs.txt / judge_filtered.jsonl already have content
# (e.g. from an earlier manual r1+r2 run), keep them as the starting point
# instead of wiping them — this run only adds NEW rounds on top. Also skip
# past any round directories that already have a completed
# attacker_results.json, so a re-run doesn't regenerate rounds that already
# finished.
START_ROUND=1
while [ -f "$ROUNDS_DIR/r${START_ROUND}/attacker_results.json" ]; do
    START_ROUND=$(( START_ROUND + 1 ))
done
n_seed_good=$(grep -c . "$CUMULATIVE_GOOD_SLUGS" || true)
if [ "$n_seed_good" -gt 0 ] || [ "$START_ROUND" -gt 1 ]; then
    echo "Resuming: $n_seed_good good slugs already recorded, starting at round r$START_ROUND"
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "ERROR: OPENAI_API_KEY not set (judge uses the real OpenAI API, gpt-5-mini)." >&2
    exit 1
fi
echo "Checking model server at $BASE_URL ..."
curl -sf "$BASE_URL/models" > /dev/null || {
    echo "ERROR: no model server at $BASE_URL — start it first (see smaller_attacker/serve/)." >&2
    exit 1
}

REMAINING_FILE="$PHASE1_DIR/remaining_r$((START_ROUND - 1)).txt"
comm -23 <(sort -u "$FULL_IDS_FILE") <(sort -u "$CUMULATIVE_GOOD_SLUGS") > "$REMAINING_FILE"

if [ "$START_ROUND" -gt "$MAX_ROUNDS" ]; then
    echo "START_ROUND ($START_ROUND) already exceeds MAX_ROUNDS ($MAX_ROUNDS) — nothing new to run, skipping straight to build."
fi

round_num=$((START_ROUND - 1))
for round_num in $(seq "$START_ROUND" "$MAX_ROUNDS"); do
    ROUND="r$round_num"
    PREV_ROUND="r$((round_num - 1))"
    ROUND_DIR="$ROUNDS_DIR/$ROUND"
    mkdir -p "$ROUND_DIR"

    n_remaining=$(grep -c . "$REMAINING_FILE" || true)
    n_good=$(grep -c . "$CUMULATIVE_GOOD_SLUGS" || true)
    echo ""
    echo "################################################################"
    echo "# Round $ROUND  —  good so far: $n_good / target $TARGET_GOOD  —  retrying: $n_remaining slugs"
    echo "################################################################"

    if [ "$n_remaining" -eq 0 ]; then
        echo "Nothing left to retry — stopping."
        break
    fi
    if [ "$n_good" -ge "$TARGET_GOOD" ]; then
        echo "Reached target of $TARGET_GOOD good slugs — stopping."
        break
    fi

    echo "--- Step 1: generate attacker_output.cc ---"
    GEN_ARGS=(
        "$JSONL"
        --ids-file    "$REMAINING_FILE"
        --samples-dir "$SAMPLES_DIR"
        --output-dir  "$ROUND_DIR"
        --model       "$MODEL"
        --base-url    "$BASE_URL"
        --workers     4
    )
    if [ "$round_num" -gt 1 ]; then
        GEN_ARGS+=(--with-error --prev-output-dir "$ROUNDS_DIR/$PREV_ROUND")
    fi
    python3 "$REPO_ROOT/cvebench/generate_attacker.py" "${GEN_ARGS[@]}"

    echo "--- Step 2: splice, build, run test suite ---"
    python3 "$REPO_ROOT/cvebench/patch_and_test.py" \
        "$JSONL" \
        --ids-file    "$REMAINING_FILE" \
        --samples-dir "$SAMPLES_DIR" \
        --output-dir  "$ROUND_DIR" \
        --clone-dir   "$CLONE_DIR"

    echo "--- Step 3: LLM judge THIS ROUND ONLY (real OpenAI API, gpt-5-mini) ---"
    ROUND_JUDGE_OUT="$PHASE1_DIR/judge_${ROUND}.jsonl"
    env -u OPENAI_BASE_URL python3 "$REPO_ROOT/cvebench/judge_cve_new.py" \
        "$JSONL" \
        --rounds-dir "$ROUNDS_DIR" \
        --rounds     "$ROUND" \
        --out        "$ROUND_JUDGE_OUT" \
        --ids-file   "$REMAINING_FILE" \
        --workers    4

    echo "--- Step 4: pull out this round's successes (build pass AND judge vulnerable) ---"
    ROUND_GOOD_JUDGE="$PHASE1_DIR/judge_filtered_${ROUND}.jsonl"
    ROUND_GOOD_SLUGS="$PHASE1_DIR/good_slugs_${ROUND}.txt"
    python3 "$REPO_ROOT/smaller_attacker/filter_judge.py" \
        --judge      "$ROUND_JUDGE_OUT" \
        --rounds-dir "$ROUNDS_DIR" \
        --out        "$ROUND_GOOD_JUDGE" \
        --good-slugs "$ROUND_GOOD_SLUGS"

    cat "$ROUND_GOOD_JUDGE" >> "$CUMULATIVE_GOOD_JUDGE"
    cat "$ROUND_GOOD_SLUGS" >> "$CUMULATIVE_GOOD_SLUGS"

    echo "--- Step 5: shrink the retry pool ---"
    NEXT_REMAINING="$PHASE1_DIR/remaining_${ROUND}.txt"
    comm -23 <(sort -u "$REMAINING_FILE") <(sort -u "$CUMULATIVE_GOOD_SLUGS") > "$NEXT_REMAINING"
    REMAINING_FILE="$NEXT_REMAINING"

    n_good_now=$(grep -c . "$CUMULATIVE_GOOD_SLUGS" || true)
    echo "Round $ROUND done. Cumulative good: $n_good_now. Remaining for next round: $(grep -c . "$REMAINING_FILE" || true)"
done

echo ""
echo "=== Iterative Phase 1 done for $TAG ==="
echo "Good slugs: $CUMULATIVE_GOOD_SLUGS ($(grep -c . "$CUMULATIVE_GOOD_SLUGS" || true) total)"

echo ""
echo "--- Final: build _CLEAN.json benchmark entries for all cumulative successes ---"
OUT_ROOT="$REPO_ROOT/smaller_attacker/results/$TAG/benchmark"
ALL_ROUNDS=$(seq -f 'r%g' 1 "$round_num")
python3 "$REPO_ROOT/cvebench/build_benchmark.py" \
    --judge      "$CUMULATIVE_GOOD_JUDGE" \
    --dataset    "$JSONL" \
    --samples    "$SAMPLES_DIR" \
    --rounds     "$ROUNDS_DIR" \
    --out-root   "$OUT_ROOT" \
    --only-rounds $ALL_ROUNDS

echo ""
echo "Benchmark for Phase 2: $OUT_ROOT/baseline/"
echo "Next: bash smaller_attacker/phase2_evasion.sh $TAG $MODEL $PORT 1 \\"
echo "        --dataset-dir $OUT_ROOT/baseline --slugs-file $CUMULATIVE_GOOD_SLUGS"
