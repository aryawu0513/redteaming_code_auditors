#!/usr/bin/env bash
# Serve Gemma-4-26B-A4B-it (MoE, ~4B active) as an OpenAI-compatible attacker
# on port 8100. Uses GPU 0. Reads from the local cache at
# /mnt/ssd/arjun/models/gemma_4_26b_a4b_it (already downloaded — no HF pull
# needed). Flags mirror /mnt/ssd/aryawu/MultiPL_TokenCost/experiment/bin/vllm_serve_gemma.sh,
# the known-working local reference for serving this model family.
#
# IMPORTANT: uses the SAME custom vllm build as that reference script
# (/mnt/ssd/arjun/repos/others/vllm/.venv/bin/vllm, 0.21.0+precompiled), not
# the shared miniconda vllm (0.20.0). The two are not equivalent despite
# having the same gemma4 module files — the shared build's FLASH_ATTN
# backend rejects this model's attention config even with
# --language-model-only ("partial multimodal token full attention not
# supported"); the custom build does not have this problem.
#
# Unlike Gemma-2, Gemma-4's own chat template supports the "system" role
# natively, so no --chat-template override is needed.

set -euo pipefail

VLLM_BIN="${VLLM_BIN:-/mnt/ssd/arjun/repos/others/vllm/.venv/bin/vllm}"
MODEL_PATH="/mnt/ssd/arjun/models/gemma_4_26b_a4b_it"
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"

echo "Serving gemma-4-26b-a4b-it on GPU $CUDA_VISIBLE_DEVICES, port 8100 (using $VLLM_BIN)"

"$VLLM_BIN" serve "$MODEL_PATH" \
    --served-model-name gemma4-26b-a4b-it \
    --port 8100 \
    --language-model-only \
    --limit-mm-per-prompt.image 0 \
    --limit-mm-per-prompt.audio 0 \
    --enable-auto-tool-choice \
    --reasoning-parser gemma4 \
    --tool-call-parser gemma4 \
    --attention-backend FLASH_ATTN \
    --max-model-len 131072 \
    --max-num-seqs 8
