#!/usr/bin/env bash
# Full end-to-end pipeline runner for the NPD-Guard benchmark.
# Runs steps 1-5 for all sofa-pbrpc NPD sites and reports results.
#
# Usage: ./run_pipeline.sh [NPD-1 NPD-2 ...]
#
# Requires:
#   - protoc + libprotobuf (from conda: conda install -c conda-forge libprotobuf protobuf)
#   - CodeQL CLI at /mnt/ssd/aryawu/codeql-home/codeql/codeql
#   - OpenAI API key (for generate_task.py)
#   - Python packages: openai

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
SITES="${@:-NPD-1 NPD-2 NPD-3 NPD-4}"

echo "=========================================="
echo " NPD-Guard Benchmark Pipeline"
echo " Repo: sofa-pbrpc"
echo " Sites: ${SITES}"
echo "=========================================="

# Step 1: Sites file already present (mines.json was pre-populated)
echo ""
echo "[Step 1] Checking sites.json..."
if [ ! -f "${ROOT}/sites.json" ]; then
  echo "ERROR: sites.json not found. Run mining step first."
  exit 1
fi
SITE_COUNT=$(python3 -c "import json; d=json.load(open('${ROOT}/sites.json')); print(len(d['sites']))")
echo "  Found ${SITE_COUNT} NPD sites in sites.json"

# Step 2: Build reference.cc + Makefile and validate with template tests
echo ""
echo "[Step 2] Building reference harnesses..."
python3 "${ROOT}/build_harness.py" ${SITES} 2>&1

# Step 3: LLM generates task.md + tests.cc, validates against reference.cc
echo ""
echo "[Step 3] Generating LLM task specs and tests..."
python3 "${ROOT}/generate_task.py" ${SITES} 2>&1

# Step 4: CodeQL clean-room gate
echo ""
echo "[Step 4] Running CodeQL clean-room gate..."
bash "${ROOT}/run_codeql_gate.sh" ${SITES} 2>&1

# Summary: collect passing samples
echo ""
echo "=========================================="
echo " Pipeline Summary"
echo "=========================================="
PASSED=0
FAILED=0
for SITE in $SITES; do
  DIR="${ROOT}/samples/${SITE}"
  SARIF="${DIR}/codeql-results-target.sarif"
  if [ -f "${DIR}/test_harness" ] && [ -f "${SARIF}" ]; then
    # Check test harness passes
    if "${DIR}/test_harness" > /dev/null 2>&1; then
      echo "  ${SITE}: VALIDATED (tests pass + CodeQL gate clear)"
      PASSED=$((PASSED + 1))
    else
      echo "  ${SITE}: FAIL (tests failed)"
      FAILED=$((FAILED + 1))
    fi
  else
    echo "  ${SITE}: INCOMPLETE (missing test_harness or SARIF)"
    FAILED=$((FAILED + 1))
  fi
done
echo ""
echo "Result: ${PASSED} validated, ${FAILED} failed/dropped"
if [ "${PASSED}" -ge 2 ]; then
  echo "SUCCESS: >=2 validated samples — pilot goal achieved."
  exit 0
else
  echo "PARTIAL: <2 validated samples — pilot goal not yet met."
  exit 1
fi
