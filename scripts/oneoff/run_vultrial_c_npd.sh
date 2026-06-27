#!/usr/bin/env bash
# run_vultrial_c_npd.sh — Run VulTrial on the unified benchmark.
#
# Prerequisites:
#   source .venv/bin/activate
#   export OPENAI_API_KEY=...     (for GPT-4o, default)
#   export ANTHROPIC_API_KEY=...  (for Claude models)
#
# Handcraft benchmark (default):
#   bash scripts/run_vultrial_c_npd.sh
#
# LeetCode benchmark:
#   DATASET_ROOT=$REPO_ROOT/benchmark/leetcodebench_gpt54mini \
#   VARIANTS="repository_069A7F404506 repository_3FC486D0AE27 ..." \
#     bash scripts/run_vultrial_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VT_MODEL:-gpt-4o}"
MODES="${MODES:-npd}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/leetcodebench_qwen}"
VARIANTS=(${VARIANTS:-repository_069A7F404506 repository_3FC486D0AE27 repository_6961F2970560 repository_6B249C5786A8 repository_7C95B6A69704 repository_9823AA10FA1B repository_A3BC94AC32E5 repository_B1AC850C7E87})

for MODE in $MODES; do
    for CATEGORY in baseline context_aware; do
        [ -d "$DATASET_ROOT/$CATEGORY" ] || continue
        for VARIANT in "${VARIANTS[@]}"; do
            [ -d "$DATASET_ROOT/$CATEGORY/$VARIANT" ] || continue
            echo "=== VulTrial C/NPD/$CATEGORY/$VARIANT | mode=$MODE model=$MODEL ==="
            python "$REPO_ROOT/VulTrial/run.py" \
                --dataset-path "$DATASET_ROOT/$CATEGORY/$VARIANT" \
                --output-dir   "$REPO_ROOT/VulTrial/results/$MODEL/$MODE/C/NPD/$CATEGORY" \
                --variant      "$VARIANT" \
                --mode         "$MODE" \
                --model        "$MODEL" \
                --category     "$CATEGORY" \
                --language     c \
                --save
        done
    done
done

echo "All VulTrial C/NPD runs complete."
