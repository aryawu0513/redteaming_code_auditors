#!/usr/bin/env bash
# Run OpenVul (generic mode, no NPD hint) on the attacker LeetCode dataset.
#
# Prerequisites:
#   export CUDA_VISIBLE_DEVICES=<free_gpu>
#
# Overrides:
#   SLUGS="069A7F404506" bash scripts/run_openvul_attacker_generic.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${OV_MODEL:-Leopo1d/OpenVul-Qwen3-4B-GRPO}"
DATASET_ROOT="$REPO_ROOT/attacker/datasets/C/NPD/attacker_lcb"
SLUGS="${SLUGS:-069A7F404506 3FC486D0AE27 6961F2970560 6B249C5786A8 7C95B6A69704 9823AA10FA1B A3BC94AC32E5 B1AC850C7E87}"

for SLUG in $SLUGS; do
    VARIANT_DIR="$DATASET_ROOT/repository_$SLUG"
    [[ -d "$VARIANT_DIR" ]] || { echo "[skip] $SLUG — not found"; continue; }
    echo "=== OpenVul generic attacker/$SLUG ==="
    VLLM_USE_V1=0 python "$REPO_ROOT/OpenVul/run.py" \
        --dataset-path "$VARIANT_DIR" \
        --output-dir   "$REPO_ROOT/OpenVul/results/attacker_lcb/C/NPD" \
        --variant      "repository_$SLUG" \
        --mode         generic \
        --model        "$MODEL" \
        --tp 1 --save
done

echo "All OpenVul generic attacker runs complete."
echo "Results: OpenVul/results/attacker_lcb/C/NPD/"
