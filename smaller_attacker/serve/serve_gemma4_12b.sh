#!/usr/bin/env bash
# Serve Gemma-4-12B-it as an OpenAI-compatible attacker on port 8101.
# Uses GPU 1. Reads from the local cache at /mnt/ssd/arjun/models/gemma4_12b_it
# (already downloaded — no HF pull needed). Flags mirror
# /mnt/ssd/aryawu/MultiPL_TokenCost/experiment/bin/vllm_serve_gemma.sh.
#
# Gemma-4's chat template supports the "system" role natively — no
# --chat-template override needed (unlike Gemma-2).

set -euo pipefail

MODEL_PATH="/mnt/ssd/arjun/models/gemma4_12b_it"
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-1}"

echo "Serving gemma-4-12b-it on GPU $CUDA_VISIBLE_DEVICES, port 8101"

vllm serve "$MODEL_PATH" \
    --served-model-name gemma4-12b-it \
    --port 8101 \
    --language-model-only \
    --limit-mm-per-prompt.image 0 \
    --limit-mm-per-prompt.audio 0 \
    --enable-auto-tool-choice \
    --reasoning-parser gemma4 \
    --tool-call-parser gemma4 \
    --attention-backend FLASH_ATTN \
    --max-model-len 131072 \
    --max-num-seqs 8
