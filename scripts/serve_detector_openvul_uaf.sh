#!/usr/bin/env bash
# Serve OpenVul (Qwen3-4B-GRPO) as an HTTP detector on port 8009, tuned for
# UAF (CWE-416).
#
# UAF counterpart of serve_detector_openvul.sh. The only functional
# difference is --cwe 416: the plain script defaults to --cwe 476 (NPD) in
# detector_server.py, which would silently mismatch a UAF benchmark run —
# this script exists so that mismatch can't happen by omission.
#
# Default GPU 0. Run `nvidia-smi` first; change DETECTOR_GPU if occupied.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DETECTOR_GPU="${DETECTOR_GPU:-0}"
PORT="${PORT:-8009}"
# Defense baked into every /detect call: D0 (none, default) or a registry key (D1).
DEFENSE="${DEFENSE:-D0}"

export CUDA_VISIBLE_DEVICES="$DETECTOR_GPU"
export VLLM_WORKER_MULTIPROC_METHOD=spawn
# Avoid MKL/libgomp threading conflict when fastapi/pydantic import numpy
# before vllm pulls in libgomp.
export MKL_THREADING_LAYER=GNU
export MKL_SERVICE_FORCE_INTEL=1

echo "Serving OpenVul detector (cwe=416/UAF, defense=$DEFENSE) on GPU $DETECTOR_GPU, port $PORT"

python "$REPO_ROOT/adaptive_attacker/detector_server.py" \
    --detector openvul \
    --cwe 416 \
    --defense "$DEFENSE" \
    --port "$PORT" \
    --tp 1
