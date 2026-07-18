#!/usr/bin/env bash
# run_all.sh — full pilot ablation: 2 candidate models × (Phase 1 + Phase 2).
#
# THIS IS LONG-RUNNING (~18 builds+test-suites per model in Phase 1, ~18
# slugs × 10 attack types in Phase 2). Read it, then launch it yourself —
# e.g. in a tmux/screen session:
#
#   tmux new -s smaller_attacker
#   bash smaller_attacker/run_all.sh 2>&1 | tee smaller_attacker/run_all.log
#
# Prerequisites:
#   1. VulnLLM-R detector serving in funclevel mode (Phase 2 only):
#        MODE=funclevel DETECTOR_GPU=<free gpu> bash scripts/serve_detector_vulnllmr.sh
#      (default expected at http://localhost:8008 — override DETECTOR_URL)
#   2. Both model servers already running (see smaller_attacker/serve/) —
#      this script does NOT start them for you.
#   3. GPUs 0, 1 free (GPU 3 is off limits per this repo's current convention).

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MODELS=(
    "gemma4-26b-a4b gemma4-26b-a4b-it 8100"
    "gemma4-12b     gemma4-12b-it     8101"
)

for entry in "${MODELS[@]}"; do
    read -r TAG MODEL PORT <<< "$entry"
    echo ""
    echo "################################################################"
    echo "# $TAG  ($MODEL, port $PORT)"
    echo "################################################################"

    bash smaller_attacker/phase1_gen_and_test.sh "$TAG" "$MODEL" "$PORT"
    bash smaller_attacker/phase2_evasion.sh      "$TAG" "$MODEL" "$PORT" 1
done

echo ""
echo "=== All models done. Scoring. ==="
python3 smaller_attacker/score_phase1.py
python3 smaller_attacker/score_phase2.py
