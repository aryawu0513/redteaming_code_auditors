#!/usr/bin/env bash
# run_fromscratch_cvebench_full_vulrag.sh
#
# From-scratch adaptive attack on all 128 cvebench_full slugs against Vul-RAG
# (retrieval-augmented LLM, function-level, CWE-476 knowledge base). The baseline
# gate skips slugs Vul-RAG doesn't detect on clean code; TPs are attacked.
#
# The annotation hits BOTH Vul-RAG surfaces: the gpt-4o-mini judgment AND the
# BM25 retrieval (injected comment can shift which knowledge is retrieved).
#
# Requires:
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#   - OPENAI_API_KEY set (for Vul-RAG gpt-4o-mini calls)
#
# Results → adaptive_attacker/results/vulrag_full/repository_<slug>/

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"   # Qwen refiner
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="fromscratch_v1"

[ -d "$DATASET" ] || { echo "ERROR: $DATASET not found" >&2; exit 1; }

mapfile -t SLUGS < <(ls "$DATASET" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "Vul-RAG from-scratch adaptive attack — all $TOTAL slugs"

DONE=0
for slug in "${SLUGS[@]}"; do
    echo ""; echo "==================== [$((DONE+1))/$TOTAL] $slug ===================="
    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$DATASET" \
        --detector            vulrag \
        --model               gpt-4o-mini \
        --system              vulrag_full \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG"
    (( DONE++ )) || true
done
echo ""; echo "Done — $DONE / $TOTAL. Results in adaptive_attacker/results/vulrag_full/"
