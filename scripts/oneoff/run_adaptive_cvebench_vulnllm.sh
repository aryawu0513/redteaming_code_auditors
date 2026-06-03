#!/usr/bin/env bash
# Adaptive attacker on cvebench_qwen3_27b — VulnLLM-R detector (port 8008).
# Refiner: port 8007. Run alongside run_adaptive_cvebench_openvul.sh in a separate terminal.

set -euo pipefail
cd "$(dirname "$0")/../.."

export OPENAI_BASE_URL=http://localhost:8007/v1
export OPENAI_API_KEY=token

python scripts/run_pipeline.py \
  --benchmark leetcodebench \
  --system vulnllm \
  --step adaptive \
  --dataset-root benchmark/cvebench_qwen3_27b/context_aware \
  --slugs NPD-CVE-01 NPD-CVE-02 NPD-CVE-03 NPD-CVE-04 NPD-CVE-06 NPD-CVE-07 NPD-CVE-08 NPD-CVE-10 \
  --detector-url http://localhost:8008 \
  --run-tag cvebench_vulnllm \
  --budget 5
