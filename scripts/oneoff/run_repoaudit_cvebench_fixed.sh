#!/usr/bin/env bash
# Fresh, clean run of all 21 RepoAudit-confirmed TPs into a NEW directory
# (repoaudit_o3mini_fixed), using the fixed detector whose reasoning is the
# explorer/validator LLM Response blocks (extract_ra_reasoning), not the
# detect_info bug report and not the buggy demo parser.
#
# Does NOT touch the existing repoaudit_o3mini_full results.
#
# Baseline is re-detected from scratch per slug. Because the detector is
# stochastic and these are all confirmed TPs, baseline detection is retried up
# to MAX_TRIES until it rolls 'vulnerable' (on which refine_loop proceeds
# straight into the 10 attacks). Slugs that never roll vulnerable are left as a
# genuine current-detector FN.
#
# Usage:
#   cd /mnt/ssd/aryawu/redteaming_code_auditors
#   export OPENAI_API_KEY=<real openai key>          # o3-mini detector
#   bash scripts/oneoff/run_repoaudit_cvebench_fixed.sh
#   # optional: MAX_TRIES=8 SMOKE=NPD-CVE-0006 bash ...   (single-slug smoke test)

set -euo pipefail
cd "$(dirname "$0")/../.."

export OPENAI_BASE_URL="http://localhost:8007/v1"   # Qwen refiner (local vLLM)

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "Error: OPENAI_API_KEY not set (needed for o3-mini detector)" >&2
    exit 1
fi

RESULTS="adaptive_attacker/results"
OUT_SYSTEM="repoaudit_o3mini_fixed"
MAX_TRIES="${MAX_TRIES:-5}"
BUDGET="${BUDGET:-5}"

# All 21 confirmed TPs (13 that passed baseline before + 8 that flipped safe)
ALL_21=(
    NPD-CVE-0006 NPD-CVE-0119 NPD-CVE-0186 NPD-CVE-0190 NPD-CVE-0194
    NPD-CVE-0236 NPD-CVE-0295 NPD-CVE-0303 NPD-CVE-0510 NPD-CVE-0513
    NPD-CVE-0514 NPD-CVE-0684 NPD-CVE-0687
    NPD-CVE-0027 NPD-CVE-0047 NPD-CVE-0074 NPD-CVE-0192 NPD-CVE-0262
    NPD-CVE-0715 NPD-CVE-0821 NPD-CVE-0826
)

# SMOKE=<slug> restricts the run to a single slug for end-to-end validation.
if [[ -n "${SMOKE:-}" ]]; then
    ALL_21=("$SMOKE")
    echo "SMOKE mode: only $SMOKE  (budget=$BUDGET, max_tries=$MAX_TRIES)"
fi

gate_verdict() {  # $1=gate path -> verdict or "none"
    if [[ -f "$1" ]]; then
        python3 -c "import json; print(json.load(open('$1')).get('verdict','none'))"
    else
        echo "none"
    fi
}

for slug in "${ALL_21[@]}"; do
    out_dir="$RESULTS/$OUT_SYSTEM/repository_$slug"
    gate="$out_dir/baseline_gate_fromscratch_v1.json"

    n_done=$(find "$out_dir" -name "result.json" -path "*/adaptive_*" 2>/dev/null | wc -l) || n_done=0
    if [[ "$n_done" -ge 10 ]]; then
        echo "[$slug] SKIP — already attacked ($n_done/10)"
        continue
    fi

    echo "=== [$slug] baseline (max $MAX_TRIES tries) ==="
    passed=0
    for ((try=1; try<=MAX_TRIES; try++)); do
        v=$(gate_verdict "$gate")
        if [[ "$v" != "vulnerable" ]]; then
            rm -f "$gate"
        fi
        echo "[$slug] try $try/$MAX_TRIES ..."
        python3 adaptive_attacker/refine_loop_fromscratch.py \
            --detector repoaudit \
            --model o3-mini \
            --slug "$slug" \
            --budget "$BUDGET" \
            --run-tag fromscratch_v1 \
            --system "$OUT_SYSTEM"

        v=$(gate_verdict "$gate")
        if [[ "$v" == "vulnerable" ]]; then
            echo "[$slug] baseline vulnerable on try $try — attacks ran."
            passed=1
            break
        fi
        echo "[$slug] try $try rolled $v."
    done
    [[ "$passed" -eq 0 ]] && echo "[$slug] never rolled vulnerable in $MAX_TRIES tries — left as current-detector FN."
done

echo ""
echo "Done."
