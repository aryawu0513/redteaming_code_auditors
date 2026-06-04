#!/usr/bin/env bash
# run_fromscratch_cvebench_vulnllm.sh
#
# From-scratch adaptive attack on CVE bench against VulnLLM-R.
#
# Requires:
#   - VulnLLM-R served at $DETECTOR_URL  (e.g. http://localhost:8000)
#   - Qwen refiner served at $OPENAI_BASE_URL  (e.g. http://localhost:8001/v1)
#   - OPENAI_API_KEY set (can be a dummy value if the server doesn't check it)
#
# What this does for each CVE slug:
#   1. Detects on the bare _CLEAN.json baseline — if the system can't see the
#      bug, skips (baseline_miss).
#   2. Takes the system's own NPD reasoning as the bootstrap seed.
#   3. Calls Qwen to craft a system-specific attack annotation (no pre-baked
#      annotations used — LLM decides both content and placement each round).
#   4. Runs up to $BUDGET adaptive refinement rounds.
#
# Outputs land in:
#   attacker/adaptive/results/vulnllmr/repository_<slug>/adaptive_<TYPE>_fromscratch_v1/
#     round_0.json … round_N.json   result.json

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/attacker/adaptive/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_qwen3_27b/context_aware"

DETECTOR_URL="http://localhost:8008"
export OPENAI_BASE_URL="http://localhost:8007/v1"
export OPENAI_API_KEY="dummy"
REFINER_MODEL="Qwen/Qwen3.6-27B-FP8"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

CVE_SLUGS=(
    NPD-CVE-01
    NPD-CVE-02
    NPD-CVE-03
    NPD-CVE-04
    NPD-CVE-06
    NPD-CVE-07
    NPD-CVE-08
    NPD-CVE-10
)

for slug in "${CVE_SLUGS[@]}"; do
    echo ""
    echo "========================================"
    echo "  slug: $slug"
    echo "========================================"
    python "$SCRIPT" \
        --slug         "$slug" \
        --dataset      "$DATASET" \
        --detector-url "$DETECTOR_URL" \
        --system       vulnllmr_fromscratch \
        --refiner-model "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget       "$BUDGET" \
        --run-tag      "$RUN_TAG"
done

echo ""
echo "All slugs done. Results in attacker/adaptive/results/vulnllmr_fromscratch/"
