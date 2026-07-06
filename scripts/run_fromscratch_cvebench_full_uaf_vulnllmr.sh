#!/usr/bin/env bash
# run_fromscratch_cvebench_full_uaf_vulnllmr.sh
#
# From-scratch adaptive UAF attack on all cvebench_full_uaf samples against
# VulnLLM-R in NON-AGENTIC (function-level) mode — same rationale as the NPD
# script this mirrors (run_fromscratch_cvebench_full_vulnllmr_funclevel.sh):
# no fuzz harnesses, so agentic mode is structurally mismatched; funclevel is
# the authentic mode for our function-centric benchmark.
#
# TWO PROCESSES (the mode/CWE is set on the SERVER, not here, since the
# attack reaches the detector over HTTP via --detector-url):
#
#   Terminal 1 — serve the detector tuned for UAF (bakes in --cwe 416):
#       MODE=funclevel DETECTOR_GPU=1 bash scripts/serve_detector_vulnllmr_uaf.sh
#
#   Terminal 2 — launch this attack:
#       bash scripts/run_fromscratch_cvebench_full_uaf_vulnllmr.sh
#
# Also requires the Qwen refiner served at $OPENAI_BASE_URL (default 8007) —
# scripts/serve_qwen3p6_27b_refiner.sh. The refiner prompt comes from
# adaptive_attacker_uaf/config_bootstrapper_uaf.yaml / config_refiner_uaf.yaml,
# read by refine_loop_uaf.py — nothing here controls prompt content.
#
# Results land in:
#   adaptive_attacker_uaf/results/uaf_vulnllmr_full/repository_<slug>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker_uaf/refine_loop_uaf.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full_uaf/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"
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
echo "VulnLLM-R (funclevel) from-scratch adaptive UAF attack — all $TOTAL slugs"
echo "--stop-on-any-flip: each slug halts the instant ANY attack type flips it,"
echo "instead of running all 5 types to their own flip/budget."
echo "Detector URL: $DETECTOR_URL  (must be serving MODE=funclevel, cwe=416)"
echo "Results: adaptive_attacker_uaf/results/uaf_vulnllmr_full/"
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
        --detector            vulnllmr \
        --detector-url        "$DETECTOR_URL" \
        --system              uaf_vulnllmr_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG" \
        --stop-on-any-flip
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker_uaf/results/uaf_vulnllmr_full/"
