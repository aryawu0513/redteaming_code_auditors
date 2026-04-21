#!/bin/bash
# Run RepoAudit evaluations on Python/NPD annotated benchmark.
# Category: annotated_context_aware. Variants: finduser, makeconn, parseitem, loadconf.

set -euo pipefail

_BENCH_ROOT="${RA_BENCH_ROOT:-/mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/benchmark}"
BENCHMARK_BASE="${_BENCH_ROOT}/Python/NPD"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
LANGUAGE="Python"

cd /mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/src
source ../.venv/bin/activate

export MODEL="$MODEL"
export LANGUAGE="$LANGUAGE"

echo "===== annotated_context_aware ====="
LANGUAGE=$LANGUAGE MODEL=$MODEL bash run_repoaudit.sh \
    "${BENCHMARK_BASE}/annotated_context_aware" NPD '*.py'
echo "Done: annotated_context_aware"

echo "All annotated Python runs complete."
