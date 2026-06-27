#!/usr/bin/env bash
# probe_vulnllmr_funclevel_baseline.sh
#
# Baseline-TPR probe for an ALREADY-SERVED VulnLLM-R detector (funclevel mode).
# POSTs the CLEAN (un-attacked) record of a few cvebench_full slugs to the
# running /detect endpoint and prints verdicts. All cvebench samples are
# known-vulnerable, so baseline TPR = fraction detected "vulnerable".
#
# Prereq: serve the detector in funclevel mode first, e.g.
#   MODE=funclevel DETECTOR_GPU=0 bash scripts/serve_detector_vulnllmr.sh
#
# Usage:
#   bash scripts/oneoff/probe_vulnllmr_funclevel_baseline.sh
#   bash scripts/oneoff/probe_vulnllmr_funclevel_baseline.sh NPD-CVE-0006 NPD-CVE-0027

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BASELINE_DIR="$REPO_ROOT/benchmark/cvebench_full/baseline"
BASE="${DETECTOR_URL:-http://localhost:8008}"

SLUGS=("$@")
if [ ${#SLUGS[@]} -eq 0 ]; then
    SLUGS=(NPD-CVE-0006 NPD-CVE-0025 NPD-CVE-0026 NPD-CVE-0027 NPD-CVE-0047)
fi

echo "Server: $BASE"
echo "Health: $(curl -s "$BASE/health" || echo '(no response — is the server up?)')"
echo ""

tp=0; n=0
for slug in "${SLUGS[@]}"; do
    f="$BASELINE_DIR/repository_$slug/${slug}_CLEAN.json"
    if [ ! -f "$f" ]; then echo "  $slug: MISSING $f"; continue; fi
    # Pipe the body via stdin (--data-binary @-); records can exceed the
    # command-line argument length limit if passed inline.
    resp=$(python3 -c "import json,sys; d=json.load(open('$f')); json.dump(d[0] if isinstance(d,list) else d, sys.stdout)" \
        | curl -s -X POST "$BASE/detect" -H 'Content-Type: application/json' --data-binary @-)
    verdict=$(printf '%s' "$resp" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('verdict','?'))
except Exception: print('parse_error')")
    echo "  $slug: $verdict"
    n=$((n+1))
    [ "$verdict" = "vulnerable" ] && tp=$((tp+1)) || true
done

echo ""
echo "Baseline TPR (funclevel): $tp/$n"
