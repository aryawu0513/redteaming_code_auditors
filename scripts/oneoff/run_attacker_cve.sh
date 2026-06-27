#!/usr/bin/env bash
# run_attacker_cve.sh — CVE NPD benchmark, local Qwen model.
#
# Prerequisites:
#   1. samples_cve/ has starter.cc, context.cc, tests.cc, task.md for each entry.
#   2. Run setup_cve_attacker_runs.py first to create repository_NPD-CVE-* dirs.
#   3. A model is being served on port 8007 (OpenAI-compatible API).
#
# Outputs per directory (attacker/runs/qwen3.6-27b/repository_NPD-CVE-XX/):
#   solution.{c,cc}, solution_COT.{c,cc}, ...(10 variants), trajectory.json, verification.json
#
# To rerun a specific site, delete its trajectory.json first.
# To run a subset: bash scripts/run_attacker_cve.sh attacker/runs/qwen3.6-27b/repository_NPD-CVE-01

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_PORT="${REFINER_PORT:-8007}"
MODEL="${MODEL:-openai/Qwen/Qwen3.6-27B-FP8}"
CONFIG="${CONFIG:-$REPO_ROOT/attacker/config_cve_nocheck.yaml}"
EXPERIMENTS_ROOT="${EXPERIMENTS_ROOT:-$REPO_ROOT/attacker/runs/qwen3.6-27b}"

export OPENAI_BASE_URL="http://localhost:${REFINER_PORT}/v1"
export OPENAI_API_BASE="$OPENAI_BASE_URL"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"

if ! curl -fsS "http://localhost:${REFINER_PORT}/v1/models" >/dev/null; then
    echo "ERROR: no OpenAI-compatible server reachable at http://localhost:${REFINER_PORT}/v1" >&2
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: config not found: $CONFIG" >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    DIRS=("$@")
else
    DIRS=("$EXPERIMENTS_ROOT"/repository_NPD-CVE-*)
fi

if [[ ${#DIRS[@]} -eq 0 ]]; then
    echo "ERROR: no repository_NPD-CVE-* directories found in $EXPERIMENTS_ROOT" >&2
    echo "Run: python3 scripts/setup_cve_attacker_runs.py pilot10.jsonl" >&2
    exit 1
fi

echo "=== Attacker run (CVE NPD benchmark, local model) ==="
echo "Model:   $MODEL"
echo "Config:  $CONFIG"
echo "Server:  $OPENAI_BASE_URL"
echo "Sites:   ${#DIRS[@]} repository_NPD-CVE-* directories"
echo ""

python "$REPO_ROOT/attacker/run_attacker.py" \
    --model "$MODEL" \
    --config "$CONFIG" \
    "${DIRS[@]}"
