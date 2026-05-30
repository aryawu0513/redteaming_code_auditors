#!/usr/bin/env bash
# Run adaptive refinement over the 8 valid LeetCodeBench slugs using:
#   - Qwen3.6-27B as refiner (served on port 8007)
#   - OpenVul detector via HTTP (default port 8008, pass@1 / n=1)
#
# Prerequisites (start in separate terminals):
#   1. Refiner server:
#        bash scripts/serve_qwen3p6_27b_refiner.sh
#   2. Detector server:
#        bash scripts/serve_detector_openvul.sh
#
# Results land in:
#   attacker/adaptive/results/repository_<slug>/adaptive_*_<RUN_TAG>/

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REFINER_PORT="${REFINER_PORT:-8007}"
DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
RUN_TAG="${RUN_TAG:-qwen_openvul_n1}"
DATASET="${DATASET:-$REPO_ROOT/benchmark/leetcodebench_qwen/context_aware}"
SLUGS=(${SLUGS:-069A7F404506 3FC486D0AE27 6961F2970560 6B249C5786A8 7C95B6A69704 9823AA10FA1B A3BC94AC32E5 B1AC850C7E87})

export OPENAI_BASE_URL="http://localhost:${REFINER_PORT}/v1"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"

echo "=== Adaptive refinement — LeetCodeBench (8 slugs) ==="
echo "Refiner:   $REFINER_MODEL @ $OPENAI_BASE_URL"
echo "Detector:  $DETECTOR_URL (OpenVul pass@1)"
echo "Dataset:   $DATASET"
echo "Run tag:   $RUN_TAG"
echo "Slugs:     ${SLUGS[*]}"
echo ""

# Baseline eligibility gate: skip any slug where OpenVul n=1 misses the baseline bug.
baseline_flag() {
  local slug="$1"
  local f="$REPO_ROOT/OpenVul/results/npd/C/NPD/baseline/repository_${slug}__npd__n1__C_NPD_baseline.json"
  if [[ ! -f "$f" ]]; then
    echo "MISSING"
    return
  fi
  python - <<PY
import json
from pathlib import Path
p=Path("$f")
data=json.loads(p.read_text())
def load_flag(item):
    flags=item.get("sample_flags")
    if flags:
        return flags[0]
    return item.get("flag")
flag=None
if len(data)>=2:
    flag=load_flag(data[1])
print(flag or "UNKNOWN")
PY
}

# Round-0 evasion (OpenVul n=1 context_aware vs baseline eligibility)
python "$REPO_ROOT/attacker/adaptive/compute_round_asr.py" \
    --mode openvul_round0 \
    --context-dir "$REPO_ROOT/OpenVul/results/leetcodebench_qwen/npd/C/NPD/context_aware" \
    --baseline-dir "$REPO_ROOT/OpenVul/results/npd/C/NPD/baseline" \
    --out-json "$REPO_ROOT/OpenVul/results/leetcodebench_qwen/npd/C/NPD/context_aware/round0_evasion.json"
echo ""

for slug in "${SLUGS[@]}"; do
  status="$(baseline_flag "$slug")"
  if [[ "$status" != "tp" ]]; then
    echo ">>> slug=$slug  (SKIP baseline=$status)"
    continue
  fi
  echo ">>> slug=$slug"
  python "$REPO_ROOT/attacker/adaptive/refine_loop.py" \
      --slug "$slug" \
      --dataset "$DATASET" \
      --detector-url "$DETECTOR_URL" \
      --refiner-model "$REFINER_MODEL" \
      --refiner-temperature 1.0 \
      --budget 5 \
      --run-tag "$RUN_TAG" \
      "$@"
done

python "$REPO_ROOT/attacker/adaptive/compute_round_asr.py" \
    --mode adaptive \
    --results-root "$REPO_ROOT/attacker/adaptive/results" \
    --run-tag "$RUN_TAG" \
    --baseline-dir "$REPO_ROOT/OpenVul/results/npd/C/NPD/baseline" \
    --out-json "$REPO_ROOT/attacker/adaptive/results/asr_by_round_${RUN_TAG}.json" \
    --out-csv "$REPO_ROOT/attacker/adaptive/results/asr_by_round_${RUN_TAG}.csv"

echo "Done. Results: attacker/adaptive/results/repository_*/adaptive_*_${RUN_TAG}/"
