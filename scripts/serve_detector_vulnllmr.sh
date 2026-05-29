#!/usr/bin/env bash
# Serve VulnLLM-R-7B (agent scaffold mode) as an HTTP detector on port 8008.
# Used by the mini-swe-agent adaptive attacker via detect_cli.py.
#
# Default GPU 3. Run `nvidia-smi` first; change DETECTOR_GPU if occupied.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DETECTOR_GPU="${DETECTOR_GPU:-3}"
PORT="${PORT:-8008}"

export CUDA_VISIBLE_DEVICES="$DETECTOR_GPU"
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export MKL_THREADING_LAYER=GNU
export MKL_SERVICE_FORCE_INTEL=1

echo "Serving VulnLLM-R detector on GPU $DETECTOR_GPU, port $PORT"

python "$REPO_ROOT/attacker/adaptive/detector_server.py" \
    --detector vulnllmr \
    --port "$PORT" \
    --tp 1
