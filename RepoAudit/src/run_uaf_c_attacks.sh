#!/bin/bash
# Run all RepoAudit evaluations on C/UAF benchmark.
# Categories: clean, dpi, context_aware. Variants: freeitem, dropconn, relogger, rmentry.

set -euo pipefail

_BENCH_ROOT="${RA_BENCH_ROOT:-/mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/benchmark}"
BENCHMARK_BASE="${_BENCH_ROOT}/C/UAF"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
LANGUAGE="Cpp"

cd /mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/src
source ../.venv/bin/activate

export MODEL="$MODEL"
export LANGUAGE="$LANGUAGE"
export RA_BUG_TYPE="UAF"

for CATEGORY in safe buggy context_aware; do #dpi
    echo "===== $CATEGORY ====="
    LANGUAGE=$LANGUAGE MODEL=$MODEL bash run_repoaudit.sh \
        "${BENCHMARK_BASE}/${CATEGORY}" UAF '*.c'
    echo "Done: $CATEGORY"
done

echo "All runs complete."
