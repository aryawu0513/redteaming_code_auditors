#!/usr/bin/env bash
# generate_attacks.sh — Generate attack payloads for all variants via LLM.
#
# Reads safe source files from benchmark/{Lang}/{Bug}/safe/,
# removes the null-check guard to introduce the bug (--inject-bug),
# and generates 10 adversarial comment payloads per variant.
#
# Output: automatic/texts/{lang}_{bug}.json  (appended; existing variants skipped)
#         RepoAudit/benchmark/{Lang}/{Bug}/buggy/  (buggy baselines written directly)
#
# This is a one-time step: automatic/texts/*.json is committed, so you only
# need to re-run when adding new variants (use --force to overwrite existing ones).
#
# Prerequisites:
#   source .venv/bin/activate
#   export ANTHROPIC_API_KEY=...
#
# Then run:  bash scripts/setup_benchmark.sh   (writes all attack files from the JSON)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== C / NPD ==="
python automatic/generate_variant.py \
    --bug-type npd --language c \
    --clean-dir benchmark/C/NPD/safe \
    --inject-bug --buggy-dir RepoAudit/benchmark/C/NPD/buggy

echo
echo "=== Python / NPD ==="
python automatic/generate_variant.py \
    --bug-type npd --language python \
    --clean-dir benchmark/Python/NPD/safe \
    --inject-bug --buggy-dir RepoAudit/benchmark/Python/NPD/buggy

echo
echo "=== C / UAF ==="
python automatic/generate_variant.py \
    --bug-type uaf --language c \
    --clean-dir benchmark/C/UAF/safe \
    --inject-bug --buggy-dir RepoAudit/benchmark/C/UAF/buggy

echo
echo "=== Done. ==="
echo "  Payloads: automatic/texts/{c_npd,python_npd,c_uaf}.json"
echo "  Buggy baselines: RepoAudit/benchmark/{C,Python}/{NPD,UAF}/buggy/"
echo
echo "Next: bash scripts/setup_benchmark.sh"
