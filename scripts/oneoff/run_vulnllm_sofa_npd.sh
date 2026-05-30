#!/usr/bin/env bash
# run_vulnllm_sofa_npd.sh — Run VulnLLM-R on the sofa-pbrpc NPD benchmark.
#
# Prerequisites:
#   source VulnLLM-R/.venv/bin/activate
#   nvidia-smi  →  export CUDA_VISIBLE_DEVICES=<id>
#
# Usage:
#   CUDA_VISIBLE_DEVICES=0 bash scripts/run_vulnllm_sofa_npd.sh
#
# To target a different benchmark root:
#   DATASET_ROOT=$REPO_ROOT/benchmark/sofa_qwen3_27b \
#     bash scripts/run_vulnllm_sofa_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VL_MODEL:-UCSB-SURFI/VulnLLM-R-7B}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/sofa_qwen3_27b}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/VulnLLM-R/results/sofa/C/NPD/policy}"
VARIANTS=(${VARIANTS:-NPD-1 NPD-2 NPD-3 NPD-4})
LANGUAGE="${LANGUAGE:-cpp}"

cd "$REPO_ROOT/VulnLLM-R"
for CATEGORY in baseline context_aware; do
    [ -d "$DATASET_ROOT/$CATEGORY" ] || continue
    for VARIANT in "${VARIANTS[@]}"; do
        [ -d "$DATASET_ROOT/$CATEGORY/repository_$VARIANT" ] || continue
        echo "=== VulnLLM-R sofa/$CATEGORY/repository_$VARIANT ==="
        VLLM_USE_V1=0 python -m vulscan.test.test \
            --output_dir   "$RESULTS_ROOT/$CATEGORY" \
            --dataset_path "$DATASET_ROOT/$CATEGORY/repository_$VARIANT" \
            --language "$LANGUAGE" --model "$MODEL" \
            --use_cot --use_policy --vllm --tp 1 --max_tokens 4096 --save
    done
done

echo "All VulnLLM-R sofa NPD runs complete."
