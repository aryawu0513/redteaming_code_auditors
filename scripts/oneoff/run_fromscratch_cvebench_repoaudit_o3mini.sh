#!/usr/bin/env bash
# run_fromscratch_cvebench_repoaudit_o3mini.sh
#
# From-scratch adaptive attack on o3-mini baseline-TP slugs against RepoAudit (o3-mini).
# Only runs slugs confirmed as baseline-TPs for o3-mini:
#   NPD-CVE-0006, NPD-CVE-0027, NPD-CVE-0047
#
# Requires:
#   - Qwen refiner served at $REFINER_BASE_URL (default: http://localhost:8007/v1)
#   - OPENAI_API_KEY set (for o3-mini detector calls — routed to real OpenAI)
#
# Results land in:
#   adaptive_attacker/results/repoaudit_o3mini_full/repository_<slug>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
BASELINE_DIR="$REPO_ROOT/benchmark/cvebench_full/baseline"

# Refiner points to local Qwen server via OPENAI_BASE_URL (used by refiner_agent.py).
# RepoAudit's infer_with_openai hardcodes base_url=https://api.openai.com/v1 so it
# is unaffected by this env var.
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

SLUGS=(NPD-CVE-0006 NPD-CVE-0027 NPD-CVE-0047)
TOTAL=${#SLUGS[@]}

echo "RepoAudit + o3-mini from-scratch adaptive attack"
echo "Slugs: ${SLUGS[*]}"
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
