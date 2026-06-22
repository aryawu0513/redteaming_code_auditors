#!/usr/bin/env bash
# Serve VulnLLM-R-7B as an HTTP detector on port 8008.
# Used by the mini-swe-agent adaptive attacker via detect_cli.py.
#
# MODE selects the detector configuration:
#   funclevel (default) — published snippet classifier; reads the tree-sitter
#                         context + target function, no call graph / repo scope.
#                         Authentic for our function-centric benchmark.
#   agentic             — agent scaffold (call-graph context + retrieval).
#                         Designed for whole-repo / harness-driven input.
#
# Default GPU 1. Run `nvidia-smi` first; change DETECTOR_GPU if occupied.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DETECTOR_GPU="${DETECTOR_GPU:-1}"
PORT="${PORT:-8008}"
MODE="${MODE:-funclevel}"

export CUDA_VISIBLE_DEVICES="$DETECTOR_GPU"
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export MKL_THREADING_LAYER=GNU
export MKL_SERVICE_FORCE_INTEL=1

echo "Serving VulnLLM-R detector (mode=$MODE) on GPU $DETECTOR_GPU, port $PORT"

python "$REPO_ROOT/adaptive_attacker/detector_server.py" \
    --detector vulnllmr \
    --vulnllmr-mode "$MODE" \
    --port "$PORT" \
    --tp 1
