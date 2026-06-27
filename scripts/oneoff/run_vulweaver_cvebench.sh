#!/usr/bin/env bash
# run_vulweaver_cvebench.sh — drive VulWeaver's RQ4 (C/C++) whole-repo pipeline
# on our spliced cvebench_full repos.
#
# PREREQUISITES (one-time):
#   1. bash scripts/oneoff/install_vulweaver_deps.sh   (uv venv + graphviz + JDK + Joern,
#      no sudo/conda). It writes scripts/oneoff/.vulweaver_env.sh, auto-sourced below.
#   2. export OPENROUTER_API_KEY=<key>   (DeepSeek routed via OpenRouter; LLM_URL/MODEL
#      default to openrouter + deepseek/deepseek-chat, override via env if desired)
#
# Long-running (Joern UDG + LLM reasoning). Inspect, then run it yourself.
# Prints an OpenRouter $ cost report for the run at the end.
#
# Usage:
#   scripts/oneoff/run_vulweaver_cvebench.sh [N_SLUGS]
#     N_SLUGS: optional cap (default: all 128). Start with 5 for a smoke test.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Self-contained env from install_vulweaver_deps.sh (uv venv + portable JDK +
# JOERN_PATH + graphviz lib path). Source it unless the caller already has one.
ENV_FILE="$REPO_ROOT/scripts/oneoff/.vulweaver_env.sh"
[[ -z "${JOERN_PATH:-}" && -f "$ENV_FILE" ]] && source "$ENV_FILE"
VW="$REPO_ROOT/VulWeaver"
SIM="$VW/evaluation/RQ4/simulation"
# Tag isolates dataset/cache/outputs so a smoke run never clobbers the full run
# (override: VW_TAG=cvebench_smoke5 scripts/oneoff/run_vulweaver_cvebench.sh 5).
TAG="${VW_TAG:-cvebench_full}"
VARIANT="CLEAN"
LIMIT_ARG=""
[[ "${1:-}" =~ ^[0-9]+$ ]] && LIMIT_ARG="--limit $1"

: "${JOERN_PATH:?set JOERN_PATH (source scripts/oneoff/.vulweaver_env.sh or run install_vulweaver_deps.sh)}"
: "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY (DeepSeek via OpenRouter)}"
export VULWEAVER_LLM_URL="${VULWEAVER_LLM_URL:-https://openrouter.ai/api/v1/chat/completions}"
export VULWEAVER_LLM_MODEL="${VULWEAVER_LLM_MODEL:-deepseek/deepseek-chat}"

DATASET="$VW/evaluation/RQ4/cvebench_dataset/${TAG}_${VARIANT}.json"
CACHE="$SIM/context_${TAG}"
TARGET_PROJECT="$SIM/target_project"
OUTPUT="$SIM/outputs_${TAG}"

# --- cost tracking: OpenRouter meters cumulative USD usage per key. Snapshot
# total_usage before/after -> exact $ for THIS whole run (UDG enhancement +
# api-extract + reasoning), provider-authoritative, no per-call plumbing. ---
or_usage() {  # echoes cumulative total_usage in USD (or empty on failure)
    curl -s --max-time 20 -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        "https://openrouter.ai/api/v1/credits" 2>/dev/null \
    | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)["data"]; print(d.get("total_usage", d.get("usage","")))
except Exception: print("")'
}
USAGE_START="$(or_usage)"
echo "### cost: OpenRouter usage at start = \$${USAGE_START:-?}"

echo "### 1/3  prep: reformat + clone-copy + splice attacker fn (+ extract sensitive APIs)"
python3 "$REPO_ROOT/scripts/oneoff/prep_vulweaver_cvebench.py" \
    --tag "$TAG" --variant "$VARIANT" --extract-api $LIMIT_ARG

echo "### 2/3  Joern UDG construction + holistic context extraction (slicing)"
export VULWEAVER_PRIMEVUL_JSON="$DATASET"
export VULWEAVER_CACHE_DIR="$CACHE"
export VULWEAVER_TARGET_PROJECT="$TARGET_PROJECT"
cd "$SIM"
# run_simulation imports `src.Constructing_Enhanced_UDG.*` (needs VW root, which
# the script inserts) AND those modules import `Constructing_Enhanced_UDG.*` bare
# (needs $VW/src on PYTHONPATH).
PYTHONPATH="$VW/src${PYTHONPATH:+:$PYTHONPATH}" python3 run_simulation_primevul.py

echo "### 3/3  context-aware LLM reasoning + majority voting (the attack target)"
cd "$VW"
# LLM routing comes from OPENROUTER_API_KEY + VULWEAVER_LLM_URL/MODEL (env),
# same as stage 2 — no --base-url/--model needed.
PYTHONPATH=src/Context-Aware_LLM_Reasoning python3 "$SIM/run_llm_reasoning.py" \
    --primevul-worklist "$DATASET" \
    --cache-dir "$CACHE" \
    --lang c \
    --output-dir "$OUTPUT" \
    --run-id "$TAG" \
    --rounds 3 --workers 16 --resume

echo "### done. results: $OUTPUT/reasoning_results_c_${TAG}.json"
echo "###       vuln summary: $OUTPUT/reasoning_vulnerabilities_c_${TAG}.json"
echo "### baseline sanity: all samples are vulnerable -> expect mostly is_vulnerable=true"

# --- cost report ---
USAGE_END="$(or_usage)"
UDG_TOKENS="$(find "$CACHE" -name token_stats.json 2>/dev/null -exec cat {} + \
    | python3 -c 'import sys,json,re
tot=0
for m in re.finditer(r"\{[^{}]*\}", sys.stdin.read()):
    try: tot+=int(json.loads(m.group()).get("total_tokens",0))
    except Exception: pass
print(tot)' 2>/dev/null || echo "?")"
echo "### ============ COST (this run) ============"
echo "###   UDG-stage tokens (token_stats.json sum): ${UDG_TOKENS}"
if [[ -n "${USAGE_START:-}" && -n "${USAGE_END:-}" ]]; then
    python3 -c "import sys
s,e=float(sys.argv[1]),float(sys.argv[2])
print(f'###   OpenRouter spend: \${e-s:.4f}  (start \${s} -> end \${e})')" "$USAGE_START" "$USAGE_END"
else
    echo "###   OpenRouter spend: unavailable (credits API gave no usage) — check https://openrouter.ai/activity"
fi
echo "### =========================================="
