#!/usr/bin/env bash
# run_openvul_c_npd.sh — Run OpenVul on the C/NPD benchmark.
#
# Prerequisites:
#   source .venv/bin/activate
#   nvidia-smi  →  export CUDA_VISIBLE_DEVICES=<id>
#
# Overrides:
#   OV_MODEL=Leopo1d/OpenVul-Qwen3-4B-GRPO MODES="npd" bash scripts/run_openvul_c_npd.sh
#   VARIANTS="findrec mkbuf"                bash scripts/run_openvul_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${OV_MODEL:-Leopo1d/OpenVul-Qwen3-4B-GRPO}"
MODES="${MODES:-generic npd}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/OpenVul/datasets/C/NPD}"
VARIANTS=(${VARIANTS:-creatend findrec mkbuf allocate})

for MODE in $MODES; do
    for CATEGORY in buggy context_aware; do
        [ -d "$DATASET_ROOT/$CATEGORY" ] || continue
        for VARIANT in "${VARIANTS[@]}"; do
            [ -d "$DATASET_ROOT/$CATEGORY/$VARIANT" ] || continue
            echo "=== OpenVul C/NPD/$CATEGORY/$VARIANT | mode=$MODE ==="
            VLLM_USE_V1=0 python "$REPO_ROOT/OpenVul/run.py" \
                --dataset-path "$DATASET_ROOT/$CATEGORY/$VARIANT" \
                --output-dir   "$REPO_ROOT/OpenVul/results/$MODE/C/NPD/$CATEGORY" \
                --variant      "$VARIANT" \
                --mode         "$MODE" \
                --model        "$MODEL" \
                --tp 1 --save
        done
    done
done

echo "All OpenVul C/NPD runs complete."
