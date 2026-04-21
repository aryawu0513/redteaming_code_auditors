#!/usr/bin/env bash
# setup_defenses.sh — Apply D3/D4 labeled caches to both RepoAudit and VulnLLM-R.
#
# Reads from:
#   defenses/texts/D3_labeled/   (populated by screen_defenses.sh)
#   defenses/texts/D4_labeled/   (populated by screen_defenses.sh)
#
# Writes to:
#   RepoAudit/benchmark-defense/{D3,D4}/
#   VulnLLM-R/datasets-defense/{D3,D4}/
#
# D1/D2 are prompt-only — nothing to apply here.
# D5 acts at runtime via annotated_context_aware/ dirs already in benchmark/.
#
# Prerequisites:
#   bash scripts/screen_defenses.sh   (must run first to populate the caches)
#   bash scripts/setup_benchmark.sh   (must run first to populate benchmark/)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SUBTREES=(C/NPD C/UAF Python/NPD)

# ── Apply to RepoAudit ─────────────────────────────────────────────────────────
echo "=== Apply to RepoAudit ==="
for DEFENSE in D3 D4; do
    echo "--- $DEFENSE ---"
    for SUBTREE in "${SUBTREES[@]}"; do
        echo "  $SUBTREE"
        python defenses/apply_repoaudit.py --defense "$DEFENSE" --subtree "$SUBTREE"
    done
done

# ── Apply to VulnLLM-R ─────────────────────────────────────────────────────────
echo
echo "=== Apply to VulnLLM-R ==="
for DEFENSE in D3 D4; do
    echo "--- $DEFENSE ---"
    for SUBTREE in "${SUBTREES[@]}"; do
        echo "  $SUBTREE"
        python defenses/apply_vulnllm.py --defense "$DEFENSE" --subtree "$SUBTREE"
    done
done

echo
echo "=== Done. ==="
echo "  D3 labeled : defenses/texts/D3_labeled/"
echo "  D4 labeled : defenses/texts/D4_labeled/"
echo "  RepoAudit  : RepoAudit/benchmark-defense/{D3,D4}/"
echo "  VulnLLM-R  : VulnLLM-R/datasets-defense/{D3,D4}/"
