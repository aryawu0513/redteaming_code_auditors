#!/usr/bin/env bash
# run_fromscratch_d1adaptive_seeded_vulnllmr_funclevel.sh
#
# SEEDED ADAPTIVE-vs-DEFENSE eval (round-0 seed REUSED from the D0 run;
# only refinement adapts to D1): re-run the from-scratch adaptive attack against the
# D1-DEFENDED VulnLLM-R (funclevel), so the attacker refines *against the defense*.
# This is the fair test the static replay can't give — does the attacker adapt to
# the comment-distrust defense (outcome 2) or stall for lack of signal (outcome 1)?
#
# Uses the CURRENT registry "D1" wording (see defenses/registry.py) — the old naive
# wording is preserved there as "D1_NAIVE". Make sure the server was (re-)started
# AFTER any registry.py edit — it loads the text once at startup.
#
# --allow-seed-fallback: 12 slugs' baseline files were edited after the D0 run
# (2026-06-23/06-28, D0 ran 2026-06-14) so their old round-0 seed no longer matches
# the current target_function. Without this flag those slugs hard-fail (see the
# require_seed guard in refine_loop_fromscratch.py). With it, only those slugs get a
# fresh bootstrap seed under D1 (breaking the "identical seed" guarantee for them);
# every other slug still replays its exact D0 seed unchanged. Check round_N.json's
# "phase" field ("seed_reused" vs "fromscratch_bootstrap") to see which happened.
#
# Scoped to the 5 portfolio framings (COT + 4 TOOL) and budget 5 (round0 + r1..r5).
# --stop-on-any-flip: once any framing flips a slug, stop refining the rest instead
# of running every framing to its own flip/round-5 (saves compute; per-framing
# rounds-to-flip stats become one-sided for the cut-off framings).
# Output goes to a NEW system dir so it does NOT touch the D0 or D1_NAIVE runs.
#
# TWO SERVERS REQUIRED:
#   Terminal 1 — D1 detector (funclevel, DEFENSE=D1) on the usual port 8008
#     (stop the old D1_NAIVE server first — it holds the old text in memory):
#       MODE=funclevel DEFENSE=D1 DETECTOR_GPU=<gpu> bash scripts/serve_detector_vulnllmr.sh
#   Terminal 2 — Qwen refiner at OPENAI_BASE_URL (default 8007), on a free GPU.
#   Terminal 3 — this script (set DETECTOR_URL to match the port above).
#
# Results: adaptive_attacker/results/vulnllmr_funclevel_full_d1adaptive_seeded/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"
DATASET="$REPO_ROOT/benchmark/cvebench_full/baseline"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"      # must be the D1 server (usual port)
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="${RUN_TAG:-d1_adaptive_seeded_v1}"
SYSTEM="${SYSTEM:-vulnllmr_funclevel_full_d1adaptive_seeded}"
TYPES=(COT TOOL_ClangSA TOOL_Coverity TOOL_Frama TOOL_Fuzzer)

# sanity: confirm the detector server is actually serving D1
DEF=$(curl -s --max-time 5 "$DETECTOR_URL/health" | grep -o '"defense":"[^"]*"' || true)
echo "Detector $DETECTOR_URL health: ${DEF:-<none>}"
case "$DEF" in
  *D1*) ;;
  *) echo "WARNING: detector is not reporting defense=D1 — this must point at the D1 server." >&2 ;;
esac

mapfile -t SLUGS < <(ls "$DATASET" | sed 's/^repository_//' | sort)
TOTAL=${#SLUGS[@]}
echo "Adaptive-vs-D1 attack — $TOTAL slugs, types: ${TYPES[*]}, budget $BUDGET"
echo "Results: adaptive_attacker/results/$SYSTEM/"

DONE=0
for slug in "${SLUGS[@]}"; do
    echo ""
    echo "======== [$((DONE+1))/$TOTAL] $slug ========"
    python "$SCRIPT" \
        --slug                "$slug" \
        --dataset             "$DATASET" \
        --detector            vulnllmr \
        --detector-url        "$DETECTOR_URL" \
        --types               "${TYPES[@]}" \
        --system              "$SYSTEM" \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "$RUN_TAG" \
        --seed-round0-from    vulnllmr_funclevel_full \
        --seed-round0-tag     fromscratch_v1 \
        --allow-seed-fallback \
        --stop-on-any-flip
    (( DONE++ )) || true
done

echo ""
echo "Done — $DONE / $TOTAL slugs. Results in adaptive_attacker/results/$SYSTEM/"
echo "Compare its ASR to the D0 attack (~83-87%) and the static-replay recovery (32%):"
echo "  ASR≈D0 → defense defeated adaptively; ASR≪D0 → defense holds / refinement stalls."
