#!/usr/bin/env bash
# run_openvul_c_npd.sh — Run OpenVul on the unified benchmark.
#
# Prerequisites:
#   source .venv/bin/activate
#   nvidia-smi  →  export CUDA_VISIBLE_DEVICES=<id>
#
# Handcraft benchmark (default):
#   bash scripts/run_openvul_c_npd.sh
#
# LeetCode benchmark:
#   DATASET_ROOT=$REPO_ROOT/benchmark/leetcodebench_gpt54mini \
#   VARIANTS="repository_069A7F404506 repository_3FC486D0AE27 ..." \
#     bash scripts/run_openvul_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${OV_MODEL:-Leopo1d/OpenVul-Qwen3-4B-GRPO}"
MODES="${MODES:-npd}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/handcraft}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/OpenVul/results}"
VARIANTS=(${VARIANTS:-creatend findrec mkbuf allocate})

for MODE in $MODES; do
    for CATEGORY in baseline context_aware; do
        [ -d "$DATASET_ROOT/$CATEGORY" ] || continue

        DPATHS=(); ODIRS=(); VNAMES=()
        for VARIANT in "${VARIANTS[@]}"; do
            [ -d "$DATASET_ROOT/$CATEGORY/$VARIANT" ] || continue
            DPATHS+=("$DATASET_ROOT/$CATEGORY/$VARIANT")
            ODIRS+=("$RESULTS_ROOT/$MODE/C/NPD/$CATEGORY")
            VNAMES+=("$VARIANT")
        done
        [ ${#DPATHS[@]} -eq 0 ] && continue

        echo "=== OpenVul C/NPD/$CATEGORY — ${#DPATHS[@]} variant(s), mode=$MODE (model loaded once) ==="
        VLLM_USE_V1=0 python "$REPO_ROOT/OpenVul/run_local_bench.py" \
            --dataset-paths "${DPATHS[@]}" \
            --output-dirs   "${ODIRS[@]}" \
            --variants      "${VNAMES[@]}" \
            --mode          "$MODE" \
            --model         "$MODEL" \
            --tp 1 --save
    done
done

echo "All OpenVul C/NPD runs complete."
