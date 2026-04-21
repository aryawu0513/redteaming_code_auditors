#!/bin/bash
# Run all RepoAudit evaluations on C/MLK benchmark.
# Categories: clean, dpi, context_aware. Variants: allocbuf, getrecord, makeconn, loadcfg.
# Each category is run as one scan (all files found recursively, each file isolated).

set -euo pipefail

BENCHMARK_BASE="/mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/benchmark/C/MLK"
MODEL="claude-haiku-4-5-20251001"
LANGUAGE="Cpp"

cd /mnt/ssd/aryawu/redteaming_repoaudit/RepoAudit/src
source ../.venv/bin/activate

export MODEL="$MODEL"
export LANGUAGE="$LANGUAGE"

for CATEGORY in clean dpi context_aware; do
    echo "===== $CATEGORY ====="
    LANGUAGE=$LANGUAGE MODEL=$MODEL bash run_repoaudit.sh \
        "${BENCHMARK_BASE}/${CATEGORY}" MLK '*.c'
    echo "Done: $CATEGORY"
done

echo "All runs complete."
