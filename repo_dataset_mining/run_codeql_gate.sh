#!/usr/bin/env bash
# Pipeline step 3: CodeQL negative-control gate on reference.cc.
#
# For each sample, builds a CodeQL database from reference.cc (the fixed version)
# and runs cpp/missing-null-test. The gate REQUIRES that the known NPD dereference
# line for this site does NOT appear in the findings — confirming that the fix
# actually removes the detectable bug.
#
# This is a negative control: if the fixed line IS still flagged, the fix is
# incomplete or wrong. If it is absent, the reference is a valid safe implementation.
#
# Note: reference.cc still contains the OTHER sites' unfixed NPDs, so total
# finding count is not zero. We check only the per-site fixed line.
#
# Reference line numbers (original target.cc line + 1 guard line inserted before):
#   NPD-1: target line 270 → reference line 271  (guard before root->AddMember)
#   NPD-2: target line 207 → reference line 208  (guard before json->PushBack)
#   NPD-3: target line 525 → reference line 526  (guard before delete json)
#   NPD-4: CodeQL blind spot (interprocedural via library call) — gate skips
#
# Exits 0 if all checked sites pass; 1 otherwise.
# Usage: ./run_codeql_gate.sh [NPD-1 NPD-2 ...]

set -e

CODEQL=/mnt/ssd/aryawu/codeql-home/codeql/codeql
QUERY=/mnt/ssd/aryawu/.codeql/packages/codeql/cpp-queries/1.6.3/Critical/MissingNullTest.ql
SEARCH_PATH=/mnt/ssd/aryawu/.codeql/packages
SAMPLES_DIR="$(dirname "$0")/samples"
CONDA=/mnt/ssd/aryawu/miniconda3

CXXFLAGS="-std=c++17 -w -I${CONDA}/include \
  -I${SAMPLES_DIR}/../sofa-pbrpc/src/rapidjson/.. \
  -I${SAMPLES_DIR}/../sofa-pbrpc/src"

# Per-site: line in reference.cc that should NOT be flagged after the fix.
# = (target.cc dereference line) + 1 (one guard line inserted before).
declare -A REF_FIXED_LINE
REF_FIXED_LINE["NPD-1"]=271   # root->AddMember(name, *field_json, ...) — now guarded
REF_FIXED_LINE["NPD-2"]=208   # json->PushBack(*v, ...) — now guarded
REF_FIXED_LINE["NPD-3"]=526   # delete json — now guarded
REF_FIXED_LINE["NPD-4"]=""    # CodeQL blind spot (interprocedural via MutableMessage)

SITES="${@:-NPD-1 NPD-2 NPD-3 NPD-4}"
ALL_PASS=true

for SITE in $SITES; do
  DIR="${SAMPLES_DIR}/${SITE}"
  if [ ! -f "${DIR}/reference.cc" ]; then
    echo "${SITE}: SKIP (no reference.cc — run build_harness.py first)"
    continue
  fi

  echo "=== ${SITE}: CodeQL negative-control gate ==="
  DB="${DIR}/codeql-db-reference"

  $CODEQL database create "${DB}" \
    --language=cpp \
    --command="g++ ${CXXFLAGS} ${DIR}/reference.cc -c -o /dev/null" \
    --overwrite \
    2>&1 | grep -E "Successfully|Error|Failed" || true

  SARIF="${DIR}/codeql-results-reference.sarif"
  $CODEQL database analyze "${DB}" "${QUERY}" \
    --search-path="${SEARCH_PATH}" \
    --format=sarif-latest \
    --output="${SARIF}" \
    2>/dev/null

  TOTAL=$(python3 -c "
import json, sys
d = json.load(open('${SARIF}'))
print(len(d['runs'][0]['results']))
" 2>/dev/null || echo "0")

  FIXED_LINE="${REF_FIXED_LINE[$SITE]}"

  if [ -z "${FIXED_LINE}" ]; then
    echo "  SKIP: CodeQL blind spot for ${SITE} — MutableMessage is a library function;"
    echo "        interprocedural null flow not tracked by MissingNullTest.ql"
    continue
  fi

  # Gate: the fixed line must NOT appear in findings
  python3 -c "
import json, sys
d = json.load(open('${SARIF}'))
fixed_line = ${FIXED_LINE}
for r in d['runs'][0]['results']:
    loc = r['locations'][0]['physicalLocation']
    fname = loc['artifactLocation']['uri'].split('/')[-1]
    if fname != 'reference.cc':
        continue
    if loc.get('region', {}).get('startLine') == fixed_line:
        sys.exit(1)   # still flagged — fix incomplete
sys.exit(0)           # not flagged — fix works
" 2>/dev/null
  NOT_FLAGGED=$?

  if [ "${NOT_FLAGGED}" = "0" ]; then
    echo "  PASS: line ${FIXED_LINE} not in findings — fix removes the NPD (${TOTAL} total findings in reference.cc) ✓"
  else
    echo "  FAIL: line ${FIXED_LINE} still flagged in reference.cc — fix is incomplete"
    ALL_PASS=false
  fi
done

if $ALL_PASS; then
  echo ""
  echo "CodeQL negative-control gate: all fixed lines clear."
  exit 0
else
  echo ""
  echo "CodeQL negative-control gate: some fixed lines still flagged — check FIXES in build_harness.py."
  exit 1
fi
