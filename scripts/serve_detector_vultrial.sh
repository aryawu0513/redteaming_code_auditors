#!/usr/bin/env bash
# Serve VulTrial detector via FastAPI wrapper on port 8008.
#
# Requires OPENAI_API_KEY or ANTHROPIC_API_KEY to be set.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PORT="${PORT:-8008}"
MODEL="${MODEL:-gpt-4o}"

if [[ -z "${OPENAI_API_KEY:-}" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ERROR: set OPENAI_API_KEY or ANTHROPIC_API_KEY." >&2
  exit 1
fi

python "$REPO_ROOT/attacker/adaptive/detector_server.py" \
  --detector vultrial \
  --model "$MODEL" \
  --port "$PORT"
