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
#   DATASET_ROOT=$REPO_ROOT/benchmark/leetcodebench \
#   VARIANTS="repository_069A7F404506 repository_3FC486D0AE27 ..." \
#     bash scripts/run_vultrial_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VT_MODEL:-gpt-4o}"
MODES="${MODES:-generic npd}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/handcraft}"
VARIANTS=(${VARIANTS:-creatend findrec mkbuf allocate})

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
