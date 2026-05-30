#!/usr/bin/env bash
# Adaptive refinement vs OpenVul (n=1, pass@1) on sofa-pbrpc NPD-1/2/3.
# Refiner = local Qwen3.6-27B-FP8.
#
# Prerequisite (start FIRST, in its own terminal, wait for "Application startup complete."):
#   bash scripts/serve_qwen3p6_27b_refiner.sh      # refiner on GPU 2, port 8007
#
#   pip install sentence-transformers   # if not already installed
#
# OpenVul detector loads IN-PROCESS on DETECTOR_GPU (not the HTTP server).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_MODEL=Qwen/Qwen3.6-27B-FP8
REFINER_PORT="${REFINER_PORT:-8007}"
DETECTOR_GPU="${DETECTOR_GPU:-1}"          # GPU 2 = refiner server; GPU 0 busy
RUN_TAG="${RUN_TAG:-sofa_openvul_n1}"
DATASET="$REPO_ROOT/benchmark/sofa_qwen3_27b/context_aware"
SLUGS=("NPD-1" "NPD-2" "NPD-3")

export CUDA_VISIBLE_DEVICES=$DETECTOR_GPU
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export OPENAI_BASE_URL=http://localhost:${REFINER_PORT}/v1
export OPENAI_API_KEY=dummy

echo "=== Adaptive refinement — OpenVul (n=1) on sofa NPD-1/2/3 ==="
echo "Detector GPU: $DETECTOR_GPU (OpenVul-Qwen3-4B-GRPO, in-process)"
echo "Refiner: $REFINER_MODEL @ port $REFINER_PORT | Run tag: $RUN_TAG"

for slug in "${SLUGS[@]}"; do
  echo ">>> slug=$slug"
  python "$REPO_ROOT/attacker/adaptive/refine_loop.py" \
      --detector openvul \
      --model Leopo1d/OpenVul-Qwen3-4B-GRPO \
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
