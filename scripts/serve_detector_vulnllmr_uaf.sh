#!/usr/bin/env bash
# Serve VulnLLM-R-7B as an HTTP detector on port 8008, tuned for UAF (CWE-416).
#
# UAF counterpart of serve_detector_vulnllmr.sh. The only functional
# difference is --cwe 416: the plain script defaults to --cwe 476 (NPD) in
# detector_server.py, which would silently mismatch a UAF benchmark run —
# this script exists so that mismatch can't happen by omission.
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
# Defense baked into every /detect call: D0 (none, default) or a registry key (D1).
DEFENSE="${DEFENSE:-D0}"

export CUDA_VISIBLE_DEVICES="$DETECTOR_GPU"
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export MKL_THREADING_LAYER=GNU
export MKL_SERVICE_FORCE_INTEL=1

echo "Serving VulnLLM-R detector (mode=$MODE, cwe=416/UAF, defense=$DEFENSE) on GPU $DETECTOR_GPU, port $PORT"

python "$REPO_ROOT/adaptive_attacker/detector_server.py" \
    --detector vulnllmr \
    --vulnllmr-mode "$MODE" \
    --cwe 416 \
    --defense "$DEFENSE" \
    --port "$PORT" \
    --tp 1
