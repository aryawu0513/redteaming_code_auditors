#!/usr/bin/env bash
# launch_screening_agent.sh
#
# Runs the D3B hard-cut full-scale proxy check (defenses/d3_proxy_check.py
# --full-scale) for all four detector systems in parallel: OpenVul, VulnLLM-R
# (both screened WITH context_before/context_after/auxiliary_file, matching
# what those two detectors actually see), VulTrial and VulRAG (screened with
# target_function alone, matching what those two detectors actually see).
#
# All 125 benchmark slugs x 10 attack types x 4 systems, binary
# VERIFIABLE/UNVERIFIABLE scheme, last/winning round per (slug, type).
# Estimated cost: roughly $7-15 total on gpt-5-mini (see conversation).
#
# Requires a REAL OpenAI API key (screening_agent.py hardcodes api.openai.com).
#
# Results: defenses/screening_results/full_scale_<System>.log (stdout)
#          defenses/screening_results/full_scale_<System>.json (raw per-row labels)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/defenses/d3_proxy_check.py"
LOG_DIR="$REPO_ROOT/defenses/screening_results"

: "${OPENAI_API_KEY:?Set OPENAI_API_KEY to a REAL OpenAI key.}"

mkdir -p "$LOG_DIR"

SYSTEMS=(OpenVul VulnLLM-R VulTrial VulRAG)

for sys in "${SYSTEMS[@]}"; do
    python3 "$SCRIPT" --full-scale "$sys" 2>&1 | tee "$LOG_DIR/full_scale_${sys}.log" &
done

wait
echo ""
echo "All four systems done. Logs + raw JSON in $LOG_DIR/full_scale_<System>.{log,json}"
