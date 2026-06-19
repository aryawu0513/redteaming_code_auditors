#!/usr/bin/env bash
# run_fromscratch_cvebench_full_vulnllm.sh
#
# From-scratch adaptive attack on all 128 cvebench_full samples against VulnLLM-R.
#
# Requires:
#   - VulnLLM-R served at $DETECTOR_URL  (default: http://localhost:8008)
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#
# Build the benchmark first:
#   python3 cvebench/build_benchmark.py \
#       --judge   cvebench/judge_r1r2.jsonl \
#       --dataset cvebench/f3_nolimit_dedup_func.slim.jsonl \
#       --samples cvebench/samples_cve_fix \
#       --rounds  cvebench/rounds \
#       --out-root benchmark/cvebench_full
#
# Results land in:
#   adaptive_attacker/results/vulnllmr_full/repository_<slug>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

BASELINE_DIR="$REPO_ROOT/benchmark/cvebench_full/baseline"

if [ ! -d "$BASELINE_DIR" ]; then
    echo "ERROR: $BASELINE_DIR not found — run build_benchmark.py first."
    exit 1
fi

mapfile -t SLUGS < <(ls "$BASELINE_DIR" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "Found $TOTAL slugs in $BASELINE_DIR"

DONE=0
for slug in "${SLUGS[@]}"; do
    echo ""
    echo "========================================"
    echo "  [$((DONE+1))/$TOTAL] $slug"
    echo "========================================"
    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$DATASET" \
        --detector            vulnllmr \
        --detector-url        "$DETECTOR_URL" \
        --system              vulnllmr_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/vulnllmr_full/"
