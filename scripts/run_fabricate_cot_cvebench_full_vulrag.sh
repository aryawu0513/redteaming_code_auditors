#!/usr/bin/env bash
# run_fabricate_cot_cvebench_full_vulrag.sh
#
# Runs refine_loop_fabricate_cot.py over all 128 cvebench_full slugs
# against VulRAG (gpt-4o-mini) with budget=10. Resumes automatically.
#
# Requires:
#   - Real OPENAI_API_KEY (VulRAG uses the real OpenAI API)
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fabricate_cot.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:?OPENAI_API_KEY must be set to a real OpenAI key}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
DETECTOR_MODEL="${DETECTOR_MODEL:-gpt-4o-mini}"
BUDGET=10
RUN_TAG="fabricate_cot_v1"
SYSTEM="vulrag_fabricate_cot"

mapfile -t SLUGS < <(ls "$DATASET" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "Found $TOTAL slugs in $DATASET"
echo "System: $SYSTEM | Budget: $BUDGET | Refiner: $REFINER_MODEL | Detector model: $DETECTOR_MODEL"
echo ""

DONE=0
for slug in "${SLUGS[@]}"; do
    echo "========================================"
    echo "  [$((DONE+1))/$TOTAL] $slug"
    echo "========================================"
    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$DATASET" \
        --detector            vulrag \
        --model               "$DETECTOR_MODEL" \
        --system              "$SYSTEM" \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    echo ""
    (( DONE++ )) || true
done

echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/$SYSTEM/"
