#!/usr/bin/env bash
# Run adaptive attacker phase 1 targeting VulnLLM-R-7B as the detector,
# with local Qwen3.6-27B as the refiner.
#
# Prerequisites:
#   1. Start the refiner server first:
#        bash scripts/serve_qwen3p6_27b_refiner.sh
#      Wait until it prints "Application startup complete."
#
#   2. pip install sentence-transformers
#
# Runtime estimate: ~30-50 min on a single H100 (VulnLLM-R-7B is larger)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_MODEL=Qwen/Qwen3.6-27B
REFINER_PORT=8007
DETECTOR_GPU=3   # Use GPU 3 for the detector (GPU 1 for OpenVul, GPU 2 for refiner server)
RUN_TAG=qwen_vulnllmr_agentic

export CUDA_VISIBLE_DEVICES=$DETECTOR_GPU
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export OPENAI_BASE_URL=http://localhost:${REFINER_PORT}/v1
export OPENAI_API_KEY=dummy

echo "=== Adaptive Attacker Phase 1 — VulnLLM-R Detector + Qwen3.6-27B Refiner ==="
echo "Detector GPU: $DETECTOR_GPU  (VulnLLM-R-7B)"
echo "Refiner: $REFINER_MODEL (port $REFINER_PORT)"
echo "Run tag: $RUN_TAG"
echo "Repo: $REPO_ROOT"
echo ""

python "$REPO_ROOT/attacker/adaptive/refine_loop.py" \
    --detector vulnllmr \
    --refiner-model "$REFINER_MODEL" \
    --refiner-temperature 1.0 \
    --tp 1 \
    --budget 5 \
    --run-tag "$RUN_TAG" \
    "$@"

echo ""
echo "Done. Results in attacker/experiments/repository_069A7F404506/adaptive_*_qwen_vulnllmr_agentic/"
