#!/usr/bin/env bash
# Serve OpenVul NPD (Qwen3-4B-GRPO, n=8 majority vote) as an HTTP detector
# on port 8008. Used by the mini-swe-agent adaptive attacker via detect_cli.py.
#
# Default GPU 1. Run `nvidia-smi` first; change DETECTOR_GPU if occupied.
#
# After this prints "{detector} loaded; serving on 0.0.0.0:8008",
# launch the agent run with:
#   bash scripts/run_attacker_qwen_adaptive.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DETECTOR_GPU="${DETECTOR_GPU:-1}"
PORT="${PORT:-8008}"

export CUDA_VISIBLE_DEVICES="$DETECTOR_GPU"
export VLLM_WORKER_MULTIPROC_METHOD=spawn
# Avoid MKL/libgomp threading conflict when fastapi/pydantic import numpy
# before vllm pulls in libgomp.
export MKL_THREADING_LAYER=GNU
export MKL_SERVICE_FORCE_INTEL=1

echo "Serving OpenVul detector on GPU $DETECTOR_GPU, port $PORT"

python "$REPO_ROOT/attacker/adaptive/detector_server.py" \
    --detector openvul \
    --port "$PORT" \
    --tp 1
