#!/usr/bin/env bash
# run_openvul_sofa_npd.sh — Run OpenVul on the sofa-pbrpc NPD benchmark.
#
# Prerequisites:
#   source .venv/bin/activate
#   nvidia-smi  →  export CUDA_VISIBLE_DEVICES=<id>
#
# Usage:
#   CUDA_VISIBLE_DEVICES=0 bash scripts/run_openvul_sofa_npd.sh
#
# To target a different benchmark root:
#   DATASET_ROOT=$REPO_ROOT/benchmark/sofa_qwen3_27b \
#     bash scripts/run_openvul_sofa_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${OV_MODEL:-Leopo1d/OpenVul-Qwen3-4B-GRPO}"
MODES="${MODES:-npd}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/sofa_qwen3_27b}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/OpenVul/results/sofa}"
VARIANTS=(${VARIANTS:-NPD-1 NPD-2 NPD-3 NPD-4})
N_COMPLETIONS="${N_COMPLETIONS:-1}"

for MODE in $MODES; do
    for CATEGORY in baseline context_aware; do
        [ -d "$DATASET_ROOT/$CATEGORY" ] || continue

        # Collect all existing variant dirs into parallel arrays
        DPATHS=(); ODIRS=(); VNAMES=()
        for VARIANT in "${VARIANTS[@]}"; do
            [ -d "$DATASET_ROOT/$CATEGORY/repository_$VARIANT" ] || continue
            DPATHS+=("$DATASET_ROOT/$CATEGORY/repository_$VARIANT")
            ODIRS+=("$RESULTS_ROOT/$MODE/C/NPD/$CATEGORY")
            VNAMES+=("repository_$VARIANT")
        done
        [ ${#DPATHS[@]} -eq 0 ] && continue

        echo "=== OpenVul sofa/$CATEGORY — ${#DPATHS[@]} variant(s), mode=$MODE (model loaded once) ==="
        VLLM_USE_V1=0 python "$REPO_ROOT/OpenVul/run_local_bench.py" \
            --dataset-paths "${DPATHS[@]}" \
            --output-dirs   "${ODIRS[@]}" \
            --variants      "${VNAMES[@]}" \
            --mode          "$MODE" \
            --model         "$MODEL" \
            --tp 1 --n "$N_COMPLETIONS" --save
    done
done

echo "All OpenVul sofa NPD runs complete."
