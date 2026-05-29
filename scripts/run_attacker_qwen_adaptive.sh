#!/usr/bin/env bash
# Run the mini-swe-agent adaptive attacker against an HTTP detector.
#
# Prerequisites (start in separate terminals):
#   1. Refiner LLM (the attacker agent itself):
#        bash scripts/serve_qwen3p6_27b_refiner.sh        # port 8007
#   2. Detector under attack — pick ONE:
#        bash scripts/serve_detector_openvul.sh           # port 8008
#        bash scripts/serve_detector_vulnllmr.sh          # port 8008
#
# Then run this script. Optionally pass --types FT to limit the run.
#
# Default targets slug 069A7F404506 (matches the bootstrapped refine_loop runs).
#
# Outputs land in:
#   attacker/adaptive/agentic_results/repository_<slug>/<run_tag>/

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_PORT="${REFINER_PORT:-8007}"
DETECTOR_PORT="${DETECTOR_PORT:-8008}"
MODEL="${MODEL:-openai/Qwen/Qwen3.6-27B-FP8}"
SLUGS="${SLUGS:-069A7F404506}"
RUN_TAG="${RUN_TAG:-qwen_openvul_agentic}"

export OPENAI_BASE_URL="http://localhost:${REFINER_PORT}/v1"
export OPENAI_API_BASE="$OPENAI_BASE_URL"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
export DETECTOR_URL="http://localhost:${DETECTOR_PORT}"

# Sanity checks
if ! curl -fsS "$OPENAI_BASE_URL/models" >/dev/null; then
    echo "ERROR: refiner LLM not reachable at $OPENAI_BASE_URL" >&2
    echo "Start it with: bash scripts/serve_qwen3p6_27b_refiner.sh" >&2
    exit 1
fi
if ! curl -fsS "$DETECTOR_URL/health" >/dev/null; then
    echo "ERROR: detector not reachable at $DETECTOR_URL/health" >&2
    echo "Start it with: bash scripts/serve_detector_openvul.sh (or vulnllmr)" >&2
    exit 1
fi

echo "=== Adaptive Attacker (mini-swe-agent) ==="
echo "Refiner LLM: $MODEL @ $OPENAI_BASE_URL"
echo "Detector:    $DETECTOR_URL"
echo "Slugs:       $SLUGS"
echo "Run tag:     $RUN_TAG"
echo ""

# shellcheck disable=SC2086
python "$REPO_ROOT/attacker/adaptive/run_attacker_adaptive.py" \
    --slugs $SLUGS \
    --run-tag "$RUN_TAG" \
    --model "$MODEL" \
    "$@"

echo ""
echo "Done. Results in $REPO_ROOT/attacker/adaptive/agentic_results/"
