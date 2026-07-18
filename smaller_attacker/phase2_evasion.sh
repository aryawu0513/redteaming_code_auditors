#!/usr/bin/env bash
# phase2_evasion.sh — Phase 2: can this model write an attack payload
# (deceptive annotation) that evades a detector?
#
# Wraps the EXISTING, unmodified adaptive_attacker/refine_loop_fromscratch.py
# — just pointed at a different --refiner-model / OPENAI_BASE_URL, and
# (optionally) a different --detector.
#
# Reads the existing benchmark/cvebench_full/baseline dataset (untouched).
# Writes ONLY into smaller_attacker/results/<tag>/phase2[_<detector>]/ —
# nothing in adaptive_attacker/results/ is touched.
#
# Usage:
#   bash smaller_attacker/phase2_evasion.sh <tag> <hf_id> <port> [budget] \
#       [--dataset-dir DIR] [--slugs-file FILE] [--detector NAME] \
#       [--detector-url URL] [--detector-model MODEL] [types...]
#
# --detector: vulnllmr (default) | openvul | vultrial | vulrag
#   vulnllmr, openvul  — served detectors, need --detector-url (a local HTTP
#                        server). Default ports: vulnllmr 8008, openvul 8009.
#   vultrial, vulrag   — call the REAL OpenAI API directly, in-process/
#                        subprocess. Do NOT pass --detector-url for these —
#                        refine_loop_fromscratch.py checks --detector-url
#                        FIRST and would wrongly try to HTTP-serve them.
#                        Both are safe from the local refiner's
#                        OPENAI_BASE_URL leaking into their own calls:
#                        vulrag hardcodes base_url=https://api.openai.com/v1
#                        (detector_vulrag.py:320); vultrial strips
#                        OPENAI_BASE_URL from its subprocess env
#                        (VulTrial/run.py:343). Need --detector-model
#                        (defaults: vultrial=gpt-4o, vulrag=gpt-4o-mini) and
#                        a REAL OPENAI_API_KEY in the environment.
#
# Defaults to the pre-existing benchmark/cvebench_full/baseline dataset and
# pilot_slugs_phase2.txt. Override both to run against a model's OWN
# generated-and-judged-good samples (see phase1_judge_and_build.sh), e.g.:
#   --dataset-dir smaller_attacker/results/<tag>/benchmark/baseline \
#   --slugs-file  smaller_attacker/results/<tag>/phase1/good_slugs.txt
#
# Examples:
#   bash smaller_attacker/phase2_evasion.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100 5 \
#       --dataset-dir smaller_attacker/results/gemma4-26b-a4b/benchmark/baseline \
#       --slugs-file  smaller_attacker/results/gemma4-26b-a4b/phase1/good_slugs.txt \
#       --detector openvul --detector-url http://localhost:8009
#
#   bash smaller_attacker/phase2_evasion.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100 5 \
#       --dataset-dir smaller_attacker/results/gemma4-26b-a4b/benchmark/baseline \
#       --slugs-file  smaller_attacker/results/gemma4-26b-a4b/phase1/good_slugs.txt \
#       --detector vultrial --detector-model gpt-4o
#
# Requires:
#   - The candidate model already being served (see serve/serve_*.sh) at
#     http://localhost:<port>/v1.
#   - For vulnllmr: MODE=funclevel DETECTOR_GPU=<free gpu> bash scripts/serve_detector_vulnllmr.sh
#   - For openvul:  DETECTOR_GPU=<free gpu> bash scripts/serve_detector_openvul.sh
#   - For vultrial/vulrag: a real OPENAI_API_KEY, no local server needed.

set -uo pipefail
# NOT `set -e` at the top level: refine_loop_fromscratch.py intentionally
# raises (abort, not a silent fake-pass) when a smaller model like this one
# fails to produce a byte-verbatim `insert_before` match after 3 retries —
# that's a real, expected finding for a weaker model, not a bug. One slug
# hitting that shouldn't kill the others. Failures are caught per-slug below
# and the loop continues; a summary of failed slugs prints at the end.

TAG="${1:?usage: phase2_evasion.sh <tag> <hf_id> <port> [budget] [options] [types...]}"
MODEL="${2:?usage: phase2_evasion.sh <tag> <hf_id> <port> [budget] [options] [types...]}"
PORT="${3:?usage: phase2_evasion.sh <tag> <hf_id> <port> [budget] [options] [types...]}"
BUDGET="${4:-1}"
shift $(( $# < 4 ? $# : 4 ))

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"
SLUGS_FILE="$REPO_ROOT/smaller_attacker/pilot_slugs_phase2.txt"
DETECTOR="vulnllmr"
DETECTOR_URL_ARG=""
DETECTOR_MODEL=""

TYPES=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dataset-dir)     DATASET="$2"; shift 2 ;;
        --slugs-file)      SLUGS_FILE="$2"; shift 2 ;;
        --detector)        DETECTOR="$2"; shift 2 ;;
        --detector-url)    DETECTOR_URL_ARG="$2"; shift 2 ;;
        --detector-model)  DETECTOR_MODEL="$2"; shift 2 ;;
        *) TYPES+=("$1"); shift ;;
    esac
done
# empty TYPES => let refine_loop_fromscratch.py use its own ALL_TYPES default

case "$DETECTOR" in
    vulnllmr) DEFAULT_DETECTOR_URL="http://localhost:8008" ;;
    openvul)  DEFAULT_DETECTOR_URL="http://localhost:8009" ;;
    vultrial) DEFAULT_DETECTOR_URL=""; DETECTOR_MODEL="${DETECTOR_MODEL:-gpt-4o}" ;;
    vulrag)   DEFAULT_DETECTOR_URL=""; DETECTOR_MODEL="${DETECTOR_MODEL:-gpt-4o-mini}" ;;
    *) echo "ERROR: unknown --detector $DETECTOR (expected vulnllmr|openvul|vultrial|vulrag)" >&2; exit 1 ;;
esac
DETECTOR_URL="${DETECTOR_URL_ARG:-$DEFAULT_DETECTOR_URL}"

SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DETECTOR_SUFFIX=$([ "$DETECTOR" = "vulnllmr" ] && echo "" || echo "_$DETECTOR")
RESULTS_ROOT="$REPO_ROOT/smaller_attacker/results/$TAG/phase2${DETECTOR_SUFFIX}"

export OPENAI_BASE_URL="http://localhost:$PORT/v1"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
RUN_TAG="pilot_v1"

echo "=== Phase 2: $TAG ($MODEL) vs detector=$DETECTOR ==="
echo "Checking model server at $OPENAI_BASE_URL ..."
curl -sf "$OPENAI_BASE_URL/models" > /dev/null || {
    echo "ERROR: no model server at $OPENAI_BASE_URL — start it first (see smaller_attacker/serve/)." >&2
    exit 1
}

if [ -n "$DETECTOR_URL" ]; then
    echo "Checking detector at $DETECTOR_URL ..."
    curl -sf "$DETECTOR_URL/health" > /dev/null || {
        echo "ERROR: no detector at $DETECTOR_URL — start it first (see scripts/serve_detector_$DETECTOR.sh)." >&2
        exit 1
    }
else
    echo "Detector '$DETECTOR' calls the real OpenAI API directly (model=$DETECTOR_MODEL) — no local server to check."
    if [ "${OPENAI_API_KEY}" = "dummy" ]; then
        echo "ERROR: OPENAI_API_KEY is unset/dummy but --detector $DETECTOR needs a real OpenAI key." >&2
        exit 1
    fi
fi

mapfile -t SLUGS < "$SLUGS_FILE"
TOTAL=${#SLUGS[@]}
echo "Running $TOTAL slugs, budget=$BUDGET, types=${TYPES[*]:-<default: all 10>}"

DONE=0
FAILED_SLUGS=()
for slug in "${SLUGS[@]}"; do
    [ -z "$slug" ] && continue
    echo ""
    echo "========================================"
    echo "  [$((DONE+1))/$TOTAL] $slug"
    echo "========================================"
    OUT_DIR="$RESULTS_ROOT/repository_$slug"
    mkdir -p "$OUT_DIR"

    ARGS=(
        --slug                "$slug"
        --dataset             "$DATASET"
        --detector             "$DETECTOR"
        --system              "${TAG}_phase2${DETECTOR_SUFFIX}"
        --refiner-model       "$MODEL"
        --refiner-temperature 1.0
        --budget              "$BUDGET"
        --run-tag             "$RUN_TAG"
        --out-dir             "$OUT_DIR"
    )
    if [ -n "$DETECTOR_URL" ]; then
        ARGS+=(--detector-url "$DETECTOR_URL")
    fi
    if [ -n "$DETECTOR_MODEL" ]; then
        ARGS+=(--model "$DETECTOR_MODEL")
    fi
    if [ "${#TYPES[@]}" -gt 0 ]; then
        ARGS+=(--types "${TYPES[@]}")
    fi

    if python3 "$SCRIPT" "${ARGS[@]}"; then
        (( DONE++ )) || true
    else
        echo "  !! $slug FAILED (refiner error) — skipping, continuing with remaining slugs" >&2
        FAILED_SLUGS+=("$slug")
    fi
done

echo ""
echo "Done — $DONE / $TOTAL slugs completed cleanly."
if [ "${#FAILED_SLUGS[@]}" -gt 0 ]; then
    echo "Failed slugs (${#FAILED_SLUGS[@]}): ${FAILED_SLUGS[*]}"
    echo "(partial results for these may still exist under $RESULTS_ROOT/repository_<slug>/ for types that completed before the error)"
fi
echo "Results in $RESULTS_ROOT/"
