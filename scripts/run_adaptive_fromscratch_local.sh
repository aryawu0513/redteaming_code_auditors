#!/usr/bin/env bash
# Run the adaptive attacker in FROM-SCRATCH mode with local Qwen3.6-27B as the
# refiner. No BOOTSTRAP seed: the refiner must invent its first annotation from
# the detector's reasoning, and the shared library grows as types flip.
#
# Iteration is round-major (all active types do round N before any does N+1),
# so the first type to flip seeds the library for every other type.
#
# Prerequisites:
#   1. Start the refiner server first:
#        bash scripts/serve_qwen3p6_27b_refiner.sh
#      Wait until it prints "Application startup complete."
#   2. pip install sentence-transformers
#   3. Verify GPU occupancy with `nvidia-smi` and adjust DETECTOR_GPU below to a
#      vacant GPU (this script defaults to GPU 1; the refiner server uses GPU 2).
#
# Results land under a DISTINCT run tag so the bootstrapped results are never
# overwritten.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_MODEL=Qwen/Qwen3.6-27B-FP8
REFINER_PORT=8007
DETECTOR_PORT=8008
RUN_TAG=qwen_openvul_fromscratch

# Driver only — no GPU work happens here (refiner + detector both run as
# servers; the embedder is CPU-friendly).
export OPENAI_BASE_URL=http://localhost:${REFINER_PORT}/v1
export OPENAI_API_KEY=dummy
export DETECTOR_URL=http://localhost:${DETECTOR_PORT}

echo "=== Adaptive Attacker — FROM SCRATCH — Batch-Sync — Server-Resident Models ==="
echo "Detector:  $DETECTOR_URL  (OpenVul Qwen3-4B-GRPO, pass@1)"
echo "Refiner:   $REFINER_MODEL @ port $REFINER_PORT  (needs --max-num-seqs >= 9 for real batching)"
echo "Run tag:   $RUN_TAG  (library starts EMPTY)"
echo "Repo:      $REPO_ROOT"
echo ""

python "$REPO_ROOT/attacker/adaptive/refine_loop.py" \
    --refiner-model "$REFINER_MODEL" \
    --refiner-temperature 1.0 \
    --budget 5 \
    --from-scratch \
    --sync round \
    --run-tag "$RUN_TAG" \
    "$@"

echo ""
echo "Done. Results in attacker/adaptive/results/repository_069A7F404506/adaptive_*_${RUN_TAG}/"
echo "Accumulated library: attacker/adaptive/results/repository_069A7F404506/library_${RUN_TAG}.json"
