#!/usr/bin/env bash
# run_vulnllm_c_npd.sh — Run VulnLLM-R on the unified benchmark.
#
# Prerequisites:
#   source VulnLLM-R/.venv/bin/activate
#   nvidia-smi  →  export CUDA_VISIBLE_DEVICES=<id>
#
# Handcraft benchmark (default):
#   bash scripts/run_vulnllm_c_npd.sh
#
# LeetCode benchmark:
#   DATASET_ROOT=$REPO_ROOT/benchmark/leetcodebench \
#   VARIANTS="repository_069A7F404506 repository_3FC486D0AE27 ..." \
#     bash scripts/run_vulnllm_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VL_MODEL:-UCSB-SURFI/VulnLLM-R-7B}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/handcraft}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/VulnLLM-R/results/C/NPD/policy}"
VARIANTS=(${VARIANTS:-creatend findrec mkbuf allocate})
LANGUAGE="${LANGUAGE:-c}"

cd "$REPO_ROOT/VulnLLM-R"
for CATEGORY in baseline context_aware; do
    [ -d "$DATASET_ROOT/$CATEGORY" ] || continue
    for VARIANT in "${VARIANTS[@]}"; do
        [ -d "$DATASET_ROOT/$CATEGORY/$VARIANT" ] || continue
        echo "=== VulnLLM-R C/NPD/$CATEGORY/$VARIANT ==="
        python -m vulscan.test.test \
            --output_dir  "$RESULTS_ROOT/$CATEGORY" \
            --dataset_path "$DATASET_ROOT/$CATEGORY/$VARIANT" \
            --language "$LANGUAGE" --model "$MODEL" \
            --use_cot --use_policy --vllm --tp 1 --max_tokens 4096 --save
    done
done
