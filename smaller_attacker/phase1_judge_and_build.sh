#!/usr/bin/env bash
# phase1_judge_and_build.sh — LLM-judge Phase 1's output, keep only samples
# that are (a) not broken, (b) genuinely vulnerable per the judge, AND
# (c) already known to build + pass tests (cvebench/patch_and_test.py's
# verdict) — then build them into the _CLEAN.json format Phase 2 needs.
#
# Wraps three EXISTING, unmodified scripts:
#   cvebench/judge_cve_new.py    — the SAME LLM judge used to build the
#                                   original benchmark (see judge_r1r2.jsonl
#                                   in cvebench/ — this is not a new judge)
#   smaller_attacker/filter_judge.py  — cross-checks judge verdict against
#                                   patch_and_test.py's build/test verdict
#                                   (build_benchmark.py alone only checks
#                                   the judge verdict, not build/test)
#   cvebench/build_benchmark.py  — splices the surviving samples into
#                                   solution files + writes *_CLEAN.json
#
# Uses the REAL OpenAI API (gpt-5-mini) for the judge — NOT the local model
# server. Explicitly unsets OPENAI_BASE_URL for this step so a leftover
# local-model env var (set for Phase 1/2's OPENAI_BASE_URL) can't
# accidentally redirect judge calls to the wrong endpoint.
#
# Usage:
#   bash smaller_attacker/phase1_judge_and_build.sh <tag> [ids-file] [rounds]
#
# [rounds] is a space-separated list of round names to consider, e.g. "r1 r2"
# after running phase1_retry_round.sh for a round-2 retry. Defaults to "r1".
#
# Requires OPENAI_API_KEY (real OpenAI key) in the environment.

set -euo pipefail

TAG="${1:?usage: phase1_judge_and_build.sh <tag> [ids-file] [rounds]}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IDS_FILE="${2:-$REPO_ROOT/smaller_attacker/pilot_slugs_phase1.txt}"
ROUNDS="${3:-r1}"

PHASE1_DIR="$REPO_ROOT/smaller_attacker/results/$TAG/phase1"
ROUNDS_DIR="$PHASE1_DIR/rounds"
JUDGE_OUT="$PHASE1_DIR/judge.jsonl"
JUDGE_FILTERED="$PHASE1_DIR/judge_filtered.jsonl"
GOOD_SLUGS="$PHASE1_DIR/good_slugs.txt"
JSONL="$REPO_ROOT/cvebench/f3_nolimit_dedup_func.slim.jsonl"
SAMPLES_DIR="$REPO_ROOT/cvebench/samples_cve_fix"
OUT_ROOT="$REPO_ROOT/smaller_attacker/results/$TAG/benchmark"

for rd in $ROUNDS; do
    if [ ! -f "$ROUNDS_DIR/$rd/attacker_results.json" ]; then
        echo "ERROR: $ROUNDS_DIR/$rd/attacker_results.json not found." >&2
        exit 1
    fi
done
if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "ERROR: OPENAI_API_KEY not set (judge uses the real OpenAI API, gpt-5-mini)." >&2
    exit 1
fi

echo "=== Judge: $TAG (rounds: $ROUNDS) ==="
echo "--- Step 1: LLM judge (real OpenAI API, gpt-5-mini) ---"
env -u OPENAI_BASE_URL python3 "$REPO_ROOT/cvebench/judge_cve_new.py" \
    "$JSONL" \
    --rounds-dir "$ROUNDS_DIR" \
    --out        "$JUDGE_OUT" \
    --ids-file   "$IDS_FILE" \
    --rounds     $ROUNDS \
    --workers    4

echo "--- Step 2: cross-check judge verdict against build/test verdict ---"
python3 "$REPO_ROOT/smaller_attacker/filter_judge.py" \
    --judge      "$JUDGE_OUT" \
    --rounds-dir "$ROUNDS_DIR" \
    --out        "$JUDGE_FILTERED" \
    --good-slugs "$GOOD_SLUGS"

echo "--- Step 3: build _CLEAN.json benchmark entries for surviving samples ---"
python3 "$REPO_ROOT/cvebench/build_benchmark.py" \
    --judge      "$JUDGE_FILTERED" \
    --dataset    "$JSONL" \
    --samples    "$SAMPLES_DIR" \
    --rounds     "$ROUNDS_DIR" \
    --out-root   "$OUT_ROOT" \
    --only-rounds $ROUNDS

echo ""
echo "Done. Good slugs (build+test pass AND judge=vulnerable): $GOOD_SLUGS"
echo "Benchmark for Phase 2: $OUT_ROOT/baseline/"
echo "Next: bash smaller_attacker/phase2_evasion.sh $TAG <model> <port> 1 \\"
echo "        --dataset-dir $OUT_ROOT/baseline --slugs-file $GOOD_SLUGS"
