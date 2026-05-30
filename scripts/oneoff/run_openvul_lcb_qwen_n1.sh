#!/usr/bin/env bash
# Run OpenVul (n=1) on LeetCodeBench Qwen dataset with baseline gating:
# Only run context_aware if baseline is correctly flagged (tp).

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

MODEL="${OV_MODEL:-Leopo1d/OpenVul-Qwen3-4B-GRPO}"
DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/leetcodebench_qwen}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/OpenVul/results/leetcodebench_qwen}"
SLUGS=(${SLUGS:-069A7F404506 3FC486D0AE27 6961F2970560 6B249C5786A8 7C95B6A69704 9823AA10FA1B A3BC94AC32E5 B1AC850C7E87})

echo "=== OpenVul n=1 — LeetCodeBench Qwen (baseline-gated) ==="
echo "Model:   $MODEL"
echo "Dataset: $DATASET_ROOT"
echo "Results: $RESULTS_ROOT"
echo "Slugs:   ${SLUGS[*]}"
echo ""

VLLM_USE_V1=0 python "$REPO_ROOT/OpenVul/run_local_bench_gated.py" \
  --dataset-root "$DATASET_ROOT" \
  --output-root "$RESULTS_ROOT" \
  --model "$MODEL" \
  --tp 1 --n 1 --mode npd --save \
  --slugs "${SLUGS[@]}"
