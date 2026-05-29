#!/usr/bin/env bash
# Serve Qwen3.6-27B-FP8 as an OpenAI-compatible refiner on port 8007.
#
# Uses GPU 2 by default. Change CUDA_VISIBLE_DEVICES if occupied.
# Enables:
#   --enable-auto-tool-choice --tool-call-parser qwen3_coder  (tool cost)
#   --language-model-only                                      (text only, no vision)
#   --reasoning-parser qwen3                                   (thinking tokens)
#
# After starting, run the adaptive loop with:
#   bash scripts/run_adaptive_phase1_local.sh

set -euo pipefail

export CUDA_VISIBLE_DEVICES=2
export VLLM_USE_DEEP_GEMM=0

echo "Serving Qwen3.6-27B-FP8 on GPU $CUDA_VISIBLE_DEVICES, port 8007"

vllm serve Qwen/Qwen3.6-27B-FP8 \
    --port 8007 \
    --reasoning-parser qwen3 \
    --enable-auto-tool-choice \
    --tool-call-parser qwen3_coder \
    --language-model-only \
    --max-model-len 262144 \
    --attention-backend FLASH_ATTN \
    --max-num-seqs 10   # batch-sync fires up to 9 concurrent refiner calls per round
