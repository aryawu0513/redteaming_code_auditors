#!/usr/bin/env bash
# Adaptive attacker on cvebench_qwen3_27b — OpenVul detector (port 8009).
# Refiner: port 8007. Run alongside run_adaptive_cvebench_vulnllm.sh in a separate terminal.

set -euo pipefail
cd "$(dirname "$0")/../.."

export OPENAI_BASE_URL=http://localhost:8007/v1
export OPENAI_API_KEY=token

python scripts/run_pipeline.py \
  --benchmark leetcodebench \
  --system openvul \
  --step adaptive \
  --dataset-root benchmark/cvebench_qwen3_27b/context_aware \
  --slugs NPD-CVE-01 NPD-CVE-02 NPD-CVE-03 NPD-CVE-04 NPD-CVE-06 NPD-CVE-07 NPD-CVE-08 NPD-CVE-10 \
  --detector-url http://localhost:8009 \
  --run-tag cvebench_openvul \
  --budget 5
