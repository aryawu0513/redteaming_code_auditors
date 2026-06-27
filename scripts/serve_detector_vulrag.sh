#!/usr/bin/env bash
# Serve Vul-RAG detector via FastAPI wrapper on port 8009.
#
# Vul-RAG is function-level + API-only (no GPU). LLM calls prefer native OpenAI
# (OPENAI_API_KEY); they fall back to OpenRouter (OPENROUTER_API_KEY) only if no
# OpenAI key is set. Model auto-selects gpt-4o-mini (OpenAI) or openai/gpt-4o-mini
# (OpenRouter); override explicitly with MODEL or VULRAG_MODEL.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PORT="${PORT:-8009}"
MODEL="${MODEL:-${VULRAG_MODEL:-}}"   # empty → detector auto-picks per backend

if [[ -z "${OPENAI_API_KEY:-}" && -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "ERROR: set OPENAI_API_KEY (preferred) or OPENROUTER_API_KEY." >&2
  exit 1
fi

ARGS=(--detector vulrag --port "$PORT")
[[ -n "$MODEL" ]] && ARGS+=(--model "$MODEL")
python "$REPO_ROOT/adaptive_attacker/detector_server.py" "${ARGS[@]}"
