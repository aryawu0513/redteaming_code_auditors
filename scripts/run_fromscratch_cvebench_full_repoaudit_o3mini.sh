#!/usr/bin/env bash
# run_fromscratch_cvebench_full_repoaudit_o3mini.sh
#
# From-scratch adaptive attack on all 128 cvebench_full slugs against
# RepoAudit (o3-mini). The baseline gate inside refine_loop_fromscratch.py
# auto-skips slugs where o3-mini doesn't detect on clean code (baseline FNs).
#
# Requires:
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#   - OPENAI_API_KEY set (for o3-mini detector calls — hardcoded to real OpenAI)
#
# Results land in:
#   adaptive_attacker/results/repoaudit_o3mini_full/repository_<slug>/
#
# Already-completed slugs/attack-types are skipped automatically.
#
# Estimated cost: $50-150 depending on TP rate and slug complexity.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
BASELINE_DIR="$REPO_ROOT/benchmark/cvebench_full/baseline"

export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

if [ ! -d "$BASELINE_DIR" ]; then
    echo "ERROR: $BASELINE_DIR not found." >&2
    exit 1
fi

mapfile -t SLUGS < <(ls "$BASELINE_DIR" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "RepoAudit + o3-mini from-scratch adaptive attack — all $TOTAL slugs"
echo "Results: adaptive_attacker/results/repoaudit_o3mini_full/"
echo ""

DONE=0
for slug in "${SLUGS[@]}"; do
    echo ""
    echo "========================================"
    echo "  [$((DONE+1))/$TOTAL] $slug"
    echo "========================================"
    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$BASELINE_DIR" \
        --detector            repoaudit \
        --model               o3-mini \
        --system              repoaudit_o3mini_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/repoaudit_o3mini_full/"
