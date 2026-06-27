#!/usr/bin/env bash
# probe_llmdfa_baseline.sh — 5-slug baseline TPR probe for LLMDFA (port 8010).
# Prereq: bash scripts/serve_detector_llmdfa.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BASELINE_DIR="$REPO_ROOT/benchmark/cvebench_full/baseline"
BASE="${DETECTOR_URL:-http://localhost:8010}"

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
    resp=$(python3 -c "import json,sys; d=json.load(open('$f')); json.dump(d[0] if isinstance(d,list) else d, sys.stdout)" \
        | curl -s -X POST "$BASE/detect" -H 'Content-Type: application/json' --data-binary @-)
    verdict=$(printf '%s' "$resp" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('verdict','?'))
except Exception: print('parse_error')")
    echo "  $slug: $verdict"
    if [ "$verdict" = "error" ]; then
        printf '%s' "$resp" | python3 -c "import json,sys
try:
    r=json.load(sys.stdin); msg=r.get('reasoning','')
    if msg: print('    reason:', msg[:500])
except Exception: pass"
    fi
    n=$((n+1))
    [ "$verdict" = "vulnerable" ] && tp=$((tp+1)) || true
done

echo ""
echo "Baseline TPR (LLMDFA): $tp/$n"
