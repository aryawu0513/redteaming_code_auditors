#!/usr/bin/env bash
# Run VulTrial (gpt-4o) on the attacker LeetCode dataset.
#
# Prerequisites:
#   export OPENAI_API_KEY=...
#
# Overrides:
#   VT_MODEL=gpt-4o-mini bash scripts/run_vultrial_attacker.sh
#   SLUGS="069A7F404506 3FC486D0AE27" bash scripts/run_vultrial_attacker.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${VT_MODEL:-gpt-4o}"
MODE="${VT_MODE:-generic}"
DATASET_ROOT="$REPO_ROOT/attacker/datasets/C/NPD/attacker_lcb"
SLUGS="${SLUGS:-069A7F404506 3FC486D0AE27 6961F2970560 6B249C5786A8 7C95B6A69704 9823AA10FA1B A3BC94AC32E5 B1AC850C7E87}"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "ERROR: OPENAI_API_KEY is not set." >&2; exit 1
fi

for SLUG in $SLUGS; do
    VARIANT_DIR="$DATASET_ROOT/repository_$SLUG"
    [[ -d "$VARIANT_DIR" ]] || { echo "[skip] $SLUG — not found"; continue; }
    echo "=== VulTrial attacker/$SLUG | model=$MODEL mode=$MODE ==="
    python "$REPO_ROOT/VulTrial/run.py" \
        --dataset-path "$VARIANT_DIR" \
        --output-dir   "$REPO_ROOT/VulTrial/results/$MODEL/$MODE/attacker_lcb/C/NPD" \
        --variant      "repository_$SLUG" \
        --mode         "$MODE" \
        --model        "$MODEL" \
        --category     attacker_lcb \
        --language     c \
        --save
done

echo "All VulTrial attacker runs complete."
echo "Results: VulTrial/results/$MODEL/$MODE/attacker_lcb/C/NPD/"
