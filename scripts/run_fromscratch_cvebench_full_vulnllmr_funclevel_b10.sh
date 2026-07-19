#!/usr/bin/env bash
# run_fromscratch_cvebench_full_vulnllmr_funclevel_b10.sh
#
# Extends the budget=5 VulnLLM-R (funclevel) fromscratch_v1 run to budget=10.
# Seeds from vulnllmr_funclevel_full (b5 results) by copying to
# vulnllmr_funclevel_full_b10 on first launch, then resumes budget_exhausted
# types for 5 more rounds. Already-flipped types are skipped automatically.
#
# Requires:
#   Terminal 1 — serve the detector in funclevel mode:
#       MODE=funclevel DETECTOR_GPU=1 bash scripts/serve_detector_vulnllmr.sh
#
#   Terminal 2 — launch this script:
#       bash scripts/run_fromscratch_cvebench_full_vulnllmr_funclevel_b10.sh
#
# Also requires the Qwen refiner served at $OPENAI_BASE_URL (default 8007).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET=10
RUN_TAG="fromscratch_v1"
SYSTEM="vulnllmr_funclevel_full_b10"

SRC_DIR="$REPO_ROOT/adaptive_attacker/results/vulnllmr_funclevel_full"
DST_DIR="$REPO_ROOT/adaptive_attacker/results/$SYSTEM"

if [ ! -d "$SRC_DIR" ]; then
    echo "ERROR: $SRC_DIR not found — run the b5 script first." >&2
    exit 1
fi

if [ ! -d "$DST_DIR" ]; then
    echo "Seeding $DST_DIR from $SRC_DIR ..."
    cp -r "$SRC_DIR" "$DST_DIR"
    echo "Done copying."
else
    echo "$DST_DIR already exists — skipping copy, resuming."
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
        --detector            vulnllmr \
        --detector-url        "$DETECTOR_URL" \
        --system              "$SYSTEM" \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/$SYSTEM/"
