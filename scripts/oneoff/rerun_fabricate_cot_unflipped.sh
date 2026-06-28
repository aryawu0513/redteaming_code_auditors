#!/usr/bin/env bash
# rerun_fabricate_cot_unflipped.sh
#
# Scans a FABRICATE_COT results dir, finds every slug that was not flipped
# (budget exhausted, baseline error/miss, or bootstrap failure), and reruns
# them with a fresh run-tag. Slugs already flipped under any run-tag are
# skipped.
#
# Usage:
#   bash rerun_fabricate_cot_unflipped.sh <system> <detector> [run-tag]
#
#   system   — results subdir name, e.g. vulnllmr_fabricate_cot
#   detector — vulnllmr | openvul | vultrial | vulrag
#   run-tag  — new run tag (default: fabricate_cot_v2)
#
# Requires:
#   - vulnllmr/openvul: detector served at $DETECTOR_URL
#     (default: vulnllmr→8008, openvul→8009)
#   - vultrial/vulrag:  real OPENAI_API_KEY; no detector URL needed
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fabricate_cot.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"
RESULTS_DIR="$REPO_ROOT/adaptive_attacker/results"

export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-10}"

SYSTEM="${1:?Usage: $0 <system> <detector> [run-tag]}"
DETECTOR="${2:?Usage: $0 <system> <detector> [run-tag]}"
NEW_TAG="${3:-fabricate_cot_v2}"

# Detector-specific settings
DETECTOR_URL=""
DETECTOR_MODEL=""
case "$DETECTOR" in
    vulnllmr) DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}" ;;
    openvul)  DETECTOR_URL="${DETECTOR_URL:-http://localhost:8009}" ;;
    vultrial) DETECTOR_MODEL="${DETECTOR_MODEL:-gpt-4o}" ;;
    vulrag)   DETECTOR_MODEL="${DETECTOR_MODEL:-gpt-4o-mini}" ;;
    *) echo "Unknown detector: $DETECTOR (choices: vulnllmr openvul vultrial vulrag)" >&2; exit 1 ;;
esac

SYSTEM_DIR="$RESULTS_DIR/$SYSTEM"
if [[ ! -d "$SYSTEM_DIR" ]]; then
    echo "System dir not found: $SYSTEM_DIR" >&2
    exit 1
fi

# Collect slugs to rerun: any slug dir that has no result.json with final_verdict=safe
mapfile -t SLUGS < <(python3 -c "
import json, sys
from pathlib import Path

system_dir = Path('$SYSTEM_DIR')
rerun = []
for slug_dir in sorted(system_dir.glob('repository_*')):
    slug = slug_dir.name.replace('repository_', '')
    flipped = any(
        json.loads(f.read_text()).get('final_verdict') == 'safe'
        for f in slug_dir.rglob('result.json')
    )
    if not flipped:
        rerun.append(slug)

print('\n'.join(rerun))
")

TOTAL=${#SLUGS[@]}
echo "System:   $SYSTEM"
echo "Detector: $DETECTOR"
echo "New tag:  $NEW_TAG"
echo "Slugs to rerun: $TOTAL"
echo ""

DONE=0
for slug in "${SLUGS[@]}"; do
    echo "========================================"
    echo "  [$((DONE+1))/$TOTAL] $slug"
    echo "========================================"

    EXTRA_ARGS=()
    if [[ -n "$DETECTOR_URL" ]]; then
        EXTRA_ARGS+=(--detector-url "$DETECTOR_URL")
    fi
    if [[ -n "$DETECTOR_MODEL" ]]; then
        EXTRA_ARGS+=(--model "$DETECTOR_MODEL")
    fi

    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$DATASET" \
        --detector            "$DETECTOR" \
        "${EXTRA_ARGS[@]}" \
        --system              "$SYSTEM" \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$NEW_TAG"
    echo ""
    (( DONE++ )) || true
done

echo "Done — $DONE / $TOTAL slugs rerun."
echo "Results in adaptive_attacker/results/$SYSTEM/"
