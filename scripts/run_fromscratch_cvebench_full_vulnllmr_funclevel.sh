#!/usr/bin/env bash
# run_fromscratch_cvebench_full_vulnllmr_funclevel.sh
#
# From-scratch adaptive attack on all 128 cvebench_full samples against
# VulnLLM-R in NON-AGENTIC (function-level) mode — the published snippet
# classifier. The model reads the tree-sitter context + target function
# ("// context" / "// target function" layout it was trained on); no call
# graph, no retrieval, no whole-repo scope. This is the authentic mode for
# our function-centric benchmark (no fuzz harnesses → agentic mode is
# structurally mismatched).
#
# TWO PROCESSES (the mode is set on the SERVER, not here, because the attack
# reaches the detector over HTTP via --detector-url):
#
#   Terminal 1 — serve the detector in funclevel mode:
#       MODE=funclevel DETECTOR_GPU=1 bash scripts/serve_detector_vulnllmr.sh
#
#   Terminal 2 — launch this attack:
#       bash scripts/run_fromscratch_cvebench_full_vulnllmr_funclevel.sh
#
# Also requires the Qwen refiner served at $OPENAI_BASE_URL (default 8007).
#
# Results land in (NEW tag, does not touch the agentic vulnllmr_full):
#   adaptive_attacker/results/vulnllmr_funclevel_full/repository_<slug>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

if [ ! -d "$DATASET" ]; then
    echo "ERROR: $DATASET not found — run build_benchmark.py first." >&2
    exit 1
fi

mapfile -t SLUGS < <(ls "$DATASET" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "VulnLLM-R (funclevel) from-scratch adaptive attack — all $TOTAL slugs"
echo "Detector URL: $DETECTOR_URL  (must be serving MODE=funclevel)"
echo "Results: adaptive_attacker/results/vulnllmr_funclevel_full/"
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
        --system              vulnllmr_funclevel_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/vulnllmr_funclevel_full/"
