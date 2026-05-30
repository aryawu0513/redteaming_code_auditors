#!/usr/bin/env bash
# Adaptive refinement vs VulnLLM-R-7B (AGENTIC / agent-scaffold mode) on
# sofa-pbrpc NPD-1/2/3. Refiner = local Qwen3.6-27B-FP8.
#
# Prerequisite (start FIRST, wait for "Application startup complete."):
#   bash scripts/serve_qwen3p6_27b_refiner.sh      # refiner on GPU 2, port 8007
#
#   pip install sentence-transformers   # if not already installed
#
# VulnLLM-R loads IN-PROCESS on DETECTOR_GPU; agent scaffold is its only mode
# (policy_runs=4, n_paths=2, max_rounds=3).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_MODEL=Qwen/Qwen3.6-27B-FP8
REFINER_PORT="${REFINER_PORT:-8007}"
DETECTOR_GPU="${DETECTOR_GPU:-3}"          # GPU 2 = refiner; GPU 1 = OpenVul run; GPU 0 busy
RUN_TAG="${RUN_TAG:-sofa_vulnllmr_agentic}"
DATASET="$REPO_ROOT/benchmark/sofa_qwen3_27b/context_aware"
SLUGS=("NPD-1" "NPD-2" "NPD-3")

export CUDA_VISIBLE_DEVICES=$DETECTOR_GPU
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export OPENAI_BASE_URL=http://localhost:${REFINER_PORT}/v1
export OPENAI_API_KEY=dummy

echo "=== Adaptive refinement — VulnLLM-R (agentic) on sofa NPD-1/2/3 ==="
echo "Detector GPU: $DETECTOR_GPU (VulnLLM-R-7B agent scaffold, in-process)"
echo "Refiner: $REFINER_MODEL @ port $REFINER_PORT | Run tag: $RUN_TAG"

for slug in "${SLUGS[@]}"; do
  echo ">>> slug=$slug"
  python "$REPO_ROOT/attacker/adaptive/refine_loop.py" \
      --detector vulnllmr \
      --slug "$slug" \
      --dataset "$DATASET" \
      --refiner-model "$REFINER_MODEL" \
      --refiner-temperature 1.0 \
      --tp 1 \
      --budget 5 \
      --run-tag "$RUN_TAG" \
      "$@"
done
echo "Done. Results: attacker/adaptive/results/repository_NPD-*/adaptive_*_${RUN_TAG}/"
