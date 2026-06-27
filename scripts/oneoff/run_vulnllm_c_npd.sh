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
#   DATASET_ROOT=$REPO_ROOT/benchmark/leetcodebench_gpt54mini \
#   VARIANTS="repository_069A7F404506 repository_3FC486D0AE27 ..." \
#     bash scripts/run_vulnllm_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VL_MODEL:-UCSB-SURFI/VulnLLM-R-7B}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/leetcodebench_qwen}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/VulnLLM-R/results/C/NPD/policy_qwen}"
VARIANTS=(${VARIANTS:-repository_069A7F404506 repository_3FC486D0AE27 repository_6961F2970560 repository_6B249C5786A8 repository_7C95B6A69704 repository_9823AA10FA1B repository_A3BC94AC32E5 repository_B1AC850C7E87})
LANGUAGE="${LANGUAGE:-c}"

cd "$REPO_ROOT/VulnLLM-R"
for CATEGORY in baseline context_aware; do
    [ -d "$DATASET_ROOT/$CATEGORY" ] || continue
    for VARIANT in "${VARIANTS[@]}"; do
        [ -d "$DATASET_ROOT/$CATEGORY/$VARIANT" ] || continue
        echo "=== VulnLLM-R C/NPD/$CATEGORY/$VARIANT ==="
        VLLM_USE_V1=0 python -m vulscan.test.test \
            --output_dir  "$RESULTS_ROOT/$CATEGORY" \
            --dataset_path "$DATASET_ROOT/$CATEGORY/$VARIANT" \
            --language "$LANGUAGE" --model "$MODEL" \
            --use_cot --use_policy --vllm --tp 1 --max_tokens 4096 --save
    done
done
