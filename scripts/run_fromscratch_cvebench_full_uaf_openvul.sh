#!/usr/bin/env bash
# run_fromscratch_cvebench_full_uaf_openvul.sh
#
# From-scratch adaptive UAF attack on all cvebench_full_uaf samples against
# OpenVul.
#
# Requires:
#   - OpenVul served at $DETECTOR_URL (default: http://localhost:8009),
#     tuned for UAF: bash scripts/serve_detector_openvul_uaf.sh
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#     bash scripts/serve_qwen3p6_27b_refiner.sh
#
# --stop-on-any-flip: each slug halts the instant ANY attack type flips it,
# instead of running all 5 types to their own flip/budget.
#
# Results land in:
#   adaptive_attacker_uaf/results/uaf_openvul_full/repository_<slug>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker_uaf/refine_loop_uaf.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full_uaf/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8009}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="uaf_v1"

if [ ! -d "$DATASET" ]; then
    echo "ERROR: $DATASET not found — run cvebench/build_benchmark_uaf.py first." >&2
    exit 1
fi

mapfile -t SLUGS < <(ls "$DATASET" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "OpenVul from-scratch adaptive UAF attack — all $TOTAL slugs"
echo "Detector URL: $DETECTOR_URL  (must be serving cwe=416)"
echo "Results: adaptive_attacker_uaf/results/uaf_openvul_full/"
echo ""

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
        --system              uaf_openvul_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG" \
        --stop-on-any-flip
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker_uaf/results/uaf_openvul_full/"
