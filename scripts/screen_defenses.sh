#!/usr/bin/env bash
# screen_defenses.sh — Pre-screen the benchmark for D3, D4, and D5 defenses.
#
# D3: LLM labels every comment in-place → defenses/texts/D3_labeled/
# D4: LLM produces a per-comment audit block → defenses/texts/D4_labeled/
# D5: LLM generates honest docstrings per variant → RepoAudit/benchmark/C/NPD/annotated_context_aware/
#
# All three caches are shared between RepoAudit and VulnLLM-R.
# D1/D2 are prompt-only — nothing to precompute.
#
# Prerequisites:
#   source .venv/bin/activate
#   export ANTHROPIC_API_KEY=...
#   python attacker/build_eval_datasets.py  (must run first to populate benchmark/)
#
# Override models:
#   SCREENING_MODEL=claude-haiku-4-5-20251001 bash scripts/screen_defenses.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SUBTREES=(C/NPD)

echo "=== D3: comment screening ==="
for SUBTREE in "${SUBTREES[@]}"; do
    echo "--- $SUBTREE ---"
    python defenses/screen_benchmark.py --defense D3 --subtree "$SUBTREE"
done

echo
echo "=== D4: audit-block generation ==="
for SUBTREE in "${SUBTREES[@]}"; do
    echo "--- $SUBTREE ---"
    python defenses/screen_benchmark.py --defense D4 --subtree "$SUBTREE"
done

echo
echo "=== D5: annotator agent (honest docstrings) ==="
python defenses/annotator_agent.py --language c

echo
echo "=== Done. ==="
echo "  D3 cache: defenses/texts/D3_labeled/"
echo "  D4 cache: defenses/texts/D4_labeled/"
echo "  D5 output: RepoAudit/benchmark/C/NPD/annotated_context_aware/"
