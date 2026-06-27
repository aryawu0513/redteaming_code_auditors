#!/usr/bin/env bash
# run_fromscratch_llmdfa_0006.sh
#
# 1-slug adaptive attack on NPD-CVE-0006 against LLMDFA (port 8010).
# Use this as a smoke test before launching the full 128-slug sweep.
#
# TWO PROCESSES:
#   Terminal 1 — serve LLMDFA (no GPU; prefers OPENAI_API_KEY):
#       bash scripts/serve_detector_llmdfa.sh                           # :8010
#   Terminal 2 — launch this script (Qwen refiner must be up on 8007):
#       bash scripts/oneoff/run_fromscratch_llmdfa_0006.sh
#
# Results → adaptive_attacker/results/llmdfa_full/repository_NPD-CVE-0006/

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8010}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

echo "LLMDFA 1-slug attack — NPD-CVE-0006 (detector: $DETECTOR_URL)"
python "$SCRIPT" \
    --slug                NPD-CVE-0006 \
    --dataset             "$DATASET" \
    --detector            llmdfa \
    --detector-url        "$DETECTOR_URL" \
    --system              llmdfa_full \
    --refiner-model       "$REFINER_MODEL" \
    --refiner-temperature 1.0 \
    --budget              "$BUDGET" \
    --run-tag             "$RUN_TAG"
echo "Done. Results in adaptive_attacker/results/llmdfa_full/repository_NPD-CVE-0006/"
