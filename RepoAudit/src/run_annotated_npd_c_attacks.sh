#!/bin/bash
# Run RepoAudit evaluations on C/NPD annotated benchmark.
# Categories: annotated_clean, annotated_dpi, annotated_context_aware.

set -euo pipefail

_BENCH_ROOT="${RA_BENCH_ROOT:-/mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/benchmark}"
BENCHMARK_BASE="${_BENCH_ROOT}/C/NPD"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
LANGUAGE="Cpp"

cd /mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/src
source ../.venv/bin/activate

export MODEL="$MODEL"
export LANGUAGE="$LANGUAGE"

for CATEGORY in annotated_safe annotated_buggy annotated_context_aware; do #annotated_dpi
    echo "===== $CATEGORY ====="
    LANGUAGE=$LANGUAGE MODEL=$MODEL bash run_repoaudit.sh \
        "${BENCHMARK_BASE}/${CATEGORY}" NPD '*.c'
    echo "Done: $CATEGORY"
done

echo "All annotated runs complete."
