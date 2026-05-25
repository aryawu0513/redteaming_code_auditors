#!/usr/bin/env bash
# Run RepoAudit on the attacker LeetCode dataset.
#
# For each of the 10 slugs, analyzes:
#   - solution.c           (no attack comment — baseline)
#   - solution_COT.c, solution_FT.c, ... (10 attack variants)
#
# Two models: o3-mini and gpt-5-mini.
# Results: RepoAudit/result/dfbscan/{MODEL}/NPD/Cpp/repository_{SLUG}/
#
# Usage:
#   export OPENAI_API_KEY=...
#   bash scripts/run_repoaudit_attacker_dataset.sh
#   MODELS="o3-mini" bash scripts/run_repoaudit_attacker_dataset.sh   # single model
#   SLUGS="069A7F404506" bash scripts/run_repoaudit_attacker_dataset.sh  # single slug

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNS_DIR="$REPO_ROOT/attacker/runs/gpt-5.4-mini"
MODELS="${MODELS:-o3-mini gpt-5-mini}"
ALL_PATTERN="solution.c,solution_AA_CA.c,solution_AA_MSG.c,solution_AA_USR.c,solution_CG.c,solution_COT.c,solution_FT.c,solution_TOOL_ClangSA.c,solution_TOOL_Coverity.c,solution_TOOL_Frama.c,solution_TOOL_Fuzzer.c"
SLUGS="${SLUGS:-069A7F404506 3FC486D0AE27 6961F2970560 6B249C5786A8 7C95B6A69704 9823AA10FA1B A3BC94AC32E5 B1AC850C7E87}"

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

    for SLUG in $SLUGS; do
        REPO_DIR="$RUNS_DIR/repository_$SLUG"
        if [[ ! -d "$REPO_DIR" ]]; then
            echo "  [skip] $SLUG — directory not found"
            continue
        fi

        echo ""
        echo "  --- $SLUG: all files (clean + 10 attack variants) ---"
        LANGUAGE=Cpp MODEL="$MODEL" bash run_repoaudit.sh "$REPO_DIR" NPD "$ALL_PATTERN"
    done

    echo ""
    echo "Done: $MODEL"
done

echo ""
echo "All done."
echo "Results in: RepoAudit/result/dfbscan/{model}/NPD/Cpp/repository_{SLUG}/"
