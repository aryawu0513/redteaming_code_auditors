#!/usr/bin/env bash
# run_fromscratch_cvebench_full_openvul.sh
#
# From-scratch adaptive attack on all cvebench_full samples against OpenVul.
#
# Requires:
#   - OpenVul served at $DETECTOR_URL  (default: http://localhost:8009)
#     Run: ./scripts/serve_detector_openvul.sh
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#     Run: ./scripts/serve_qwen3p6_27b_refiner.sh
#
# Results land in:
#   adaptive_attacker/results/openvul_full/repository_<slug>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8009}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

if [ ! -d "$DATASET" ]; then
    echo "ERROR: $DATASET not found — run build_benchmark.py first."
    exit 1
fi

mapfile -t SLUGS < <(ls "$DATASET" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "Found $TOTAL slugs in $DATASET"

DONE=0
for slug in "${SLUGS[@]}"; do
    echo ""
    echo "========================================"
    echo "  [$((DONE+1))/$TOTAL] $slug"
    echo "========================================"
    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$DATASET" \
        --detector-url        "$DETECTOR_URL" \
        --system              openvul_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/openvul_full/"
