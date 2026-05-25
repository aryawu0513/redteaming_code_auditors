#!/usr/bin/env bash
# Run adaptive attacker phase 1 — slug 069A7F404506, 9 non-COT types.
#
# Prerequisites:
#   pip install sentence-transformers
#   export OPENAI_API_KEY=...
#
# Runtime estimate: ~15-25 min on a single H100 (3 detector votes/round × 5 rounds × 9 types)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
export VLLM_USE_V1=0

echo "=== Adaptive Attacker Phase 1 ==="
echo "GPU: $CUDA_VISIBLE_DEVICES"
echo "Repo: $REPO_ROOT"
echo ""

python "$REPO_ROOT/attacker/adaptive/refine_loop.py" \
    --model Leopo1d/OpenVul-Qwen3-4B-GRPO \
    --refiner-model gpt-5.4-mini \
    --refiner-temperature 0.7 \
    --tp 1 \
    --budget 5 \
    "$@"

echo ""
echo "Done. Results in attacker/experiments/repository_069A7F404506/"
