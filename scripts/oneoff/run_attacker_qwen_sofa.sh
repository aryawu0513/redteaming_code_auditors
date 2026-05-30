#!/usr/bin/env bash
# run_attacker_qwen_sofa.sh — sofa-pbrpc C++ NPD pilot, served by local Qwen.
#
# Same wiring as run_attacker_qwen.sh, but points at:
#   CONFIG  = attacker/config_sofa.yaml      (C++ stub-completion variant)
#   DIRS    = attacker/runs/qwen3.6-27b/repository_NPD-*
#
# Prerequisites:
#   1. A model is being served on port 8007 with an OpenAI-compatible API
#      (e.g. Qwen/Qwen3.6-27B-FP8 via vllm serve). Check with:
#        curl -s http://localhost:8007/v1/models
#   2. The sample dir tree (samples/NPD-{1..4}) must be in place with
#      starter.cc, tests.cc, build.yaml, task.md. The per-site repository_NPD-*
#      dirs symlink those in.
#
# Per-site outputs land in attacker/runs/qwen3.6-27b/repository_NPD-<N>/:
#   - solution.cc, solution_<TYPE>.cc (10 variants)
#   - trajectory.json
#   - verification.json
#
# To rerun a specific site, delete its trajectory.json first.
#
# To run a subset, pass them as arguments:
#   bash scripts/run_attacker_qwen_sofa.sh \
#     attacker/runs/qwen3.6-27b/repository_NPD-1

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_PORT="${REFINER_PORT:-8007}"
MODEL="${MODEL:-openai/Qwen/Qwen3.6-27B-FP8}"
CONFIG="${CONFIG:-$REPO_ROOT/attacker/config_sofa.yaml}"
EXPERIMENTS_ROOT="${EXPERIMENTS_ROOT:-$REPO_ROOT/attacker/runs/qwen3.6-27b}"

export OPENAI_BASE_URL="http://localhost:${REFINER_PORT}/v1"
export OPENAI_API_BASE="$OPENAI_BASE_URL"   # LiteLLM honors OPENAI_API_BASE
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"

# Sanity-check the server
if ! curl -fsS "http://localhost:${REFINER_PORT}/v1/models" >/dev/null; then
    echo "ERROR: no OpenAI-compatible server reachable at http://localhost:${REFINER_PORT}/v1" >&2
    exit 1
fi

# Sanity-check the config
if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: config not found: $CONFIG" >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    DIRS=("$@")
else
    DIRS=("$EXPERIMENTS_ROOT"/repository_NPD-*)
fi

echo "=== Attacker run (sofa-pbrpc C++ pilot, local model) ==="
echo "Model:   $MODEL"
echo "Config:  $CONFIG"
echo "Server:  $OPENAI_BASE_URL"
echo "Sites:   ${#DIRS[@]} repository_NPD-* directories"
echo ""

python "$REPO_ROOT/attacker/run_attacker.py" \
    --model "$MODEL" \
    --config "$CONFIG" \
    "${DIRS[@]}"
