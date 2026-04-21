#!/usr/bin/env bash
# run_repoaudit_c_npd.sh — Run RepoAudit on the C/NPD benchmark.
#
# Prerequisites:
#   source RepoAudit/.venv/bin/activate
#   export ANTHROPIC_API_KEY=...
#
# To run other bug types / languages:
#   BUG_TYPE=UAF BENCHMARK=.../C/UAF bash run_repoaudit_c_npd.sh
#   LANGUAGE=Python BENCHMARK=.../Python/NPD FILES='*.py' bash run_repoaudit_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LANGUAGE="${LANGUAGE:-Cpp}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
BUG_TYPE="${BUG_TYPE:-NPD}"
BENCHMARK="${BENCHMARK:-$REPO_ROOT/RepoAudit/benchmark/C/NPD}"
FILES="${FILES:-*.c}"

cd "$REPO_ROOT/RepoAudit/src"
for CATEGORY in buggy context_aware; do
    [ -d "$BENCHMARK/$CATEGORY" ] || continue
    echo "=== RepoAudit C/NPD/$CATEGORY ==="
    LANGUAGE="$LANGUAGE" MODEL="$MODEL" \
        bash run_repoaudit.sh "$BENCHMARK/$CATEGORY" "$BUG_TYPE" "$FILES"
done
