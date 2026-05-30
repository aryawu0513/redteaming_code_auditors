#!/usr/bin/env bash
# Run RepoAudit on the context_aware benchmark (allocate, creatend, findrec, mkbuf)
# with o3-mini and gpt-5-mini.
#
# Prerequisites:
#   export OPENAI_API_KEY=...
#
# Usage:
#   bash scripts/run_repoaudit_openai_context_aware.sh
#   MODELS="o3-mini" bash scripts/run_repoaudit_openai_context_aware.sh   # single model

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCHMARK="$REPO_ROOT/RepoAudit/benchmark/C/NPD/context_aware"
MODELS="${MODELS:-o3-mini gpt-5-mini}"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "ERROR: OPENAI_API_KEY is not set." >&2
    exit 1
fi

cd "$REPO_ROOT/RepoAudit/src"

for MODEL in $MODELS; do
    echo ""
    echo "=========================================="
    echo "  MODEL: $MODEL"
    echo "=========================================="
    LANGUAGE=Cpp MODEL="$MODEL" \
        bash run_repoaudit.sh "$BENCHMARK" NPD '*.c'
    echo "Done: $MODEL"
done

echo ""
echo "All done. Results in RepoAudit/result/dfbscan/{model}/NPD/Cpp/context_aware/"
