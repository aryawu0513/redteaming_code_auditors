#!/usr/bin/env bash
# run_repoaudit_c_npd.sh — Run RepoAudit on the unified benchmark.
#
# Prerequisites:
#   source RepoAudit/.venv/bin/activate
#   export ANTHROPIC_API_KEY=...
#
# Handcraft benchmark (default):
#   bash scripts/run_repoaudit_c_npd.sh
#
# LeetCode benchmark:
#   BENCHMARK=$REPO_ROOT/benchmark/leetcodebench bash scripts/run_repoaudit_c_npd.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LANGUAGE="${LANGUAGE:-Cpp}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
BUG_TYPE="${BUG_TYPE:-NPD}"
BENCHMARK="${BENCHMARK:-$REPO_ROOT/benchmark/handcraft}"
FILES="${FILES:-*.c}"

cd "$REPO_ROOT/RepoAudit/src"
for CATEGORY in baseline context_aware; do
    [ -d "$BENCHMARK/$CATEGORY" ] || continue
    echo "=== RepoAudit C/NPD/$CATEGORY ==="
    LANGUAGE="$LANGUAGE" MODEL="$MODEL" \
        bash run_repoaudit.sh "$BENCHMARK/$CATEGORY" "$BUG_TYPE" "$FILES"
done
