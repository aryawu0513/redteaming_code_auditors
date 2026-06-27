#!/usr/bin/env bash
# run_fromscratch_cvebench_null42_repoaudit_deepseekr1.sh
#
# Runs RepoAudit (deepseek/deepseek-r1 via OpenRouter) on the 42 CVEBench
# slugs that contain explicit NULL assignments/returns — the only ones
# RepoAudit's tree-sitter extractor can find sources for.
#
# Requires:
#   - OPENROUTER_API_KEY set
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#
# Results land in:
#   adaptive_attacker/results/repoaudit_deepseekr1_null42/repository_<slug>/
#
# Already-completed slugs/attack-types are skipped automatically.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
BASELINE_DIR="$REPO_ROOT/benchmark/cvebench_full/baseline"

export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"
SYSTEM="repoaudit_deepseekr1_null42"

# The 42 slugs with explicit = NULL / return NULL in the main code file.
# These are the only ones RepoAudit's tree-sitter NPD extractor can source.
SLUGS=(
    NPD-CVE-0006
    NPD-CVE-0027
    NPD-CVE-0047
    NPD-CVE-0053
    NPD-CVE-0054
    NPD-CVE-0074
    NPD-CVE-0078
    NPD-CVE-0186
    NPD-CVE-0190
    NPD-CVE-0192
    NPD-CVE-0194
    NPD-CVE-0198
    NPD-CVE-0236
    NPD-CVE-0238
    NPD-CVE-0240
    NPD-CVE-0262
    NPD-CVE-0292
    NPD-CVE-0295
    NPD-CVE-0297
    NPD-CVE-0303
    NPD-CVE-0305
    NPD-CVE-0379
    NPD-CVE-0394
    NPD-CVE-0396
    NPD-CVE-0397
    NPD-CVE-0580
    NPD-CVE-0672
    NPD-CVE-0684
    NPD-CVE-0685
    NPD-CVE-0686
    NPD-CVE-0687
    NPD-CVE-0688
    NPD-CVE-0691
    NPD-CVE-0694
    NPD-CVE-0715
    NPD-CVE-0736
    NPD-CVE-0785
    NPD-CVE-0822
    NPD-CVE-0823
    NPD-CVE-0825
    NPD-CVE-0826
    NPD-CVE-0827
)

TOTAL=${#SLUGS[@]}
echo "RepoAudit + deepseek/deepseek-r1 (OpenRouter) — $TOTAL NULL-reachable slugs"
echo "Results: adaptive_attacker/results/$SYSTEM/"
echo ""

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo "ERROR: OPENROUTER_API_KEY is not set." >&2
    exit 1
fi

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
        --model               "deepseek/deepseek-r1" \
        --system              "$SYSTEM" \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs."
echo "Results in adaptive_attacker/results/$SYSTEM/"
