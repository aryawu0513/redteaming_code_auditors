#!/bin/bash
# Run all RepoAudit evaluations on Python/NPD benchmark.
# Categories: safe, buggy, dpi, context_aware. Variants: finduser, makeconn, parseitem, loadconf.

set -euo pipefail

_BENCH_ROOT="${RA_BENCH_ROOT:-/mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/benchmark}"
BENCHMARK_BASE="${_BENCH_ROOT}/Python/NPD"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
LANGUAGE="Python"

cd /mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/src
source ../.venv/bin/activate

export MODEL="$MODEL"
export LANGUAGE="$LANGUAGE"

for CATEGORY in safe buggy context_aware; do #dpi
    echo "===== $CATEGORY ====="
    LANGUAGE=$LANGUAGE MODEL=$MODEL bash run_repoaudit.sh \
        "${BENCHMARK_BASE}/${CATEGORY}" NPD '*.py'
    echo "Done: $CATEGORY"
done

echo "All runs complete."
