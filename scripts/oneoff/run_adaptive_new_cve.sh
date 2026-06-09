#!/usr/bin/env bash
# run_adaptive_new_cve.sh
#
# From-scratch adaptive attack on new CVE NPD samples.
#   VulnLLM-R (port 8008) on 4 detectable slugs
#   OpenVul   (port 8009) on 7 detectable slugs
#
# Requires:
#   VulnLLM-R served: ./scripts/serve_detector_vulnllmr.sh   (port 8008)
#   OpenVul served:   ./scripts/serve_detector_openvul.sh    (port 8009)
#   Qwen served:      port 8007

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/attacker/adaptive/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_new/context_aware"

export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="${RUN_TAG:-fromscratch_v1}"

VULNLLMR_URL="http://localhost:8008"
OPENVUL_URL="http://localhost:8009"

# 0211 excluded: always-null findKey/end stubs make NPD unreachable (OpenVul FP)
# 0216 excluded: Tensor::buffer_ always null → trivially detectable, no interproc reasoning
VULNLLMR_SLUGS=(NPD-CVE-0020 NPD-CVE-0051 NPD-CVE-0263 NPD-CVE-0273)
OPENVUL_SLUGS=(NPD-CVE-0020 NPD-CVE-0051 NPD-CVE-0263 NPD-CVE-0282 NPD-CVE-0009)

echo "================================================================"
echo " Adaptive attack — new CVE NPD samples"
echo " Refiner: $OPENAI_BASE_URL ($REFINER_MODEL)"
echo " Budget:  $BUDGET rounds | Tag: $RUN_TAG"
echo "================================================================"

run_attack() {
    local slug="$1" detector_url="$2" system="$3" detector="$4"
    echo ""
    echo "========================================"
    echo "  [$system] slug: $slug"
    echo "========================================"
    python3 "$SCRIPT" \
        --slug            "$slug" \
        --dataset         "$DATASET" \
        --detector-url    "$detector_url" \
        --detector        "$detector" \
        --system          "$system" \
        --refiner-model   "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget          "$BUDGET" \
        --run-tag         "$RUN_TAG"
}

echo ""
echo "════════════════════════════════════════"
echo " VulnLLM-R adaptive (${#VULNLLMR_SLUGS[@]} slugs)"
echo "════════════════════════════════════════"
for slug in "${VULNLLMR_SLUGS[@]}"; do
    run_attack "$slug" "$VULNLLMR_URL" "vulnllmr_fromscratch" "vulnllmr"
done

echo ""
echo "════════════════════════════════════════"
echo " OpenVul adaptive (${#OPENVUL_SLUGS[@]} slugs)"
echo "════════════════════════════════════════"
for slug in "${OPENVUL_SLUGS[@]}"; do
    run_attack "$slug" "$OPENVUL_URL" "openvul_fromscratch" "openvul"
done

echo ""
echo "All done."
echo "Results in attacker/adaptive/results/vulnllmr_fromscratch/ and openvul_fromscratch/"
