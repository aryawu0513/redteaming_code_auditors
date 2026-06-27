#!/usr/bin/env bash
# run_vulnllm_agentic_c_npd.sh — Run VulnLLM-R agent scaffold on the unified benchmark.
#
# Mirrors run_vulnllm_c_npd.sh but invokes the agentic scaffold
# (agent_scaffold/scan.py --dataset) instead of the JSON-dataset test runner.
# Both consume the same benchmark/$CATEGORY/$VARIANT/ layout produced by
# attacker/build_eval_datasets.py.
#
# Prerequisites:
#   source VulnLLM-R/.venv/bin/activate
#   nvidia-smi  →  export CUDA_VISIBLE_DEVICES=<id>
#
# Handcraft benchmark (default):
#   bash scripts/run_vulnllm_agentic_c_npd.sh
#
# LeetCode benchmark:
#   DATASET_ROOT=$REPO_ROOT/benchmark/leetcodebench_qwen \
#   VARIANTS="repository_069A7F404506 repository_3FC486D0AE27 ..." \
#     bash scripts/run_vulnllm_agentic_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VL_MODEL:-UCSB-SURFI/VulnLLM-R-7B}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/leetcodebench_qwen}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/VulnLLM-R/results/agent_scaffold}"
VARIANTS=(${VARIANTS:-repository_069A7F404506 repository_3FC486D0AE27 repository_6961F2970560 repository_6B249C5786A8 repository_7C95B6A69704 repository_9823AA10FA1B repository_A3BC94AC32E5 repository_B1AC850C7E87})
LANGUAGE="${LANGUAGE:-c}"
N_PATHS="${N_PATHS:-2}"
MAX_ROUNDS="${MAX_ROUNDS:-3}"
POLICY_RUNS="${POLICY_RUNS:-0}"
MAX_TOKENS="${MAX_TOKENS:-4096}"

cd "$REPO_ROOT/VulnLLM-R"
for CATEGORY in baseline context_aware; do
    [ -d "$DATASET_ROOT/$CATEGORY" ] || continue
    for VARIANT in "${VARIANTS[@]}"; do
        [ -d "$DATASET_ROOT/$CATEGORY/$VARIANT" ] || continue
        echo "=== Agent scaffold C/NPD/$CATEGORY/$VARIANT ==="
        python -m agent_scaffold.scan \
            --dataset    "$DATASET_ROOT/$CATEGORY/$VARIANT" \
            --output-dir "$RESULTS_ROOT/$CATEGORY/$VARIANT" \
            --language   "$LANGUAGE" \
            --vllm       "$MODEL" \
            --n-paths    "$N_PATHS" \
            --max-rounds "$MAX_ROUNDS" \
            --policy-runs "$POLICY_RUNS" \
            --max-tokens "$MAX_TOKENS"
    done
done
