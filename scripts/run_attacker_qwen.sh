#!/usr/bin/env bash
# run_attacker_qwen.sh — Run the attacker against a local vLLM-served model.
#
# Prerequisites:
#   1. A model is being served on port 8007 with an OpenAI-compatible API
#      (e.g. Qwen/Qwen3.6-27B via vllm serve). Check with:
#        curl -s http://localhost:8007/v1/models
#
# Raw attacker outputs land in attacker/runs/qwen3.6-27b/repository_<slug>/:
#   - solution.c, solution_<TYPE>.c (10 variants)
#   - trajectory.json
#   - verification.json
#
# To rerun a specific slug, delete its trajectory.json first.
#
# To run a subset of slugs, pass them as arguments, e.g.:
#   bash scripts/run_attacker_qwen.sh \
#     attacker/runs/qwen3.6-27b/repository_069A7F404506
#
# Build evaluator JSON datasets from these outputs with:
#   python attacker/build_eval_datasets.py \
#     --runs-dir attacker/runs/qwen3.6-27b \
#     --out-root benchmark/leetcodebench_qwen

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_PORT="${REFINER_PORT:-8007}"
MODEL="${MODEL:-openai/Qwen/Qwen3.6-27B}"
CONFIG="${CONFIG:-$REPO_ROOT/attacker/config_qwen.yaml}"
EXPERIMENTS_ROOT="${EXPERIMENTS_ROOT:-$REPO_ROOT/attacker/runs/qwen3.6-27b}"

export OPENAI_BASE_URL="http://localhost:${REFINER_PORT}/v1"
export OPENAI_API_BASE="$OPENAI_BASE_URL"   # LiteLLM honors OPENAI_API_BASE
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"

# Sanity-check the server
if ! curl -fsS "http://localhost:${REFINER_PORT}/v1/models" >/dev/null; then
    echo "ERROR: no OpenAI-compatible server reachable at http://localhost:${REFINER_PORT}/v1" >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    DIRS=("$@")
else
    DIRS=("$EXPERIMENTS_ROOT"/repository_*)
fi

echo "=== Attacker run (local model) ==="
echo "Model:   $MODEL"
echo "Config:  $CONFIG"
echo "Server:  $OPENAI_BASE_URL"
echo "Dirs:    ${#DIRS[@]} experiment directories"
echo ""

python "$REPO_ROOT/attacker/run_attacker.py" \
    --model "$MODEL" \
    --config "$CONFIG" \
    "${DIRS[@]}"
