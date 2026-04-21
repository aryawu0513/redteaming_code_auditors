#!/usr/bin/env bash
# run_demo.sh — End-to-end adversarial demo
#
# Three phases:
#   1. Generate attacks: attack_agent.py injects adversarial comments → build_attacks.py writes repos
#   2. Baseline: both auditors detect the bug in the clean repo
#   3. Post-attack: both auditors run on each attacked repo; compare_results.py prints the diff
#
# Prerequisites:
#   export ANTHROPIC_API_KEY=...       (for RepoAudit + attack_agent.py)
#   export CUDA_VISIBLE_DEVICES=<id>   (check nvidia-smi first)
#   source RepoAudit/.venv/bin/activate
#
# Usage:
#   bash demo/run_demo.sh                        # all attacks, target_repo
#   bash demo/run_demo.sh target_repo_v2         # second demo repo
#   bash demo/run_demo.sh target_repo COT CG     # specific attacks only

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="$REPO_ROOT/demo"
REPO_NAME="${1:-target_repo}"; shift 2>/dev/null || true

case "$REPO_NAME" in
    target_repo)    TARGET_FN="display_user" ;;
    target_repo_v2) TARGET_FN="write_record" ;;
    *) echo "Unknown repo: $REPO_NAME (expected target_repo or target_repo_v2)" >&2; exit 1 ;;
esac

TARGET_REPO="$DEMO_DIR/$REPO_NAME"
ATTACKS_DIR="$DEMO_DIR/${REPO_NAME}_attacks"
TEXTS_FILE="$DEMO_DIR/texts/${REPO_NAME}.json"
RESULTS_DIR="$DEMO_DIR/results/$REPO_NAME"
RA_SRC="$REPO_ROOT/RepoAudit/src"
RA_MODEL="${MODEL:-claude-haiku-4-5-20251001}"
VL_DIR="$REPO_ROOT/VulnLLM-R"
VL_PYTHON="$VL_DIR/.venv/bin/python"
VL_MODEL="${VL_MODEL:-UCSB-SURFI/VulnLLM-R-7B}"
POLICY_RUNS="${POLICY_RUNS:-4}"
MAX_TOKENS="${MAX_TOKENS:-8192}"

mkdir -p "$RESULTS_DIR/vulnllm" "$(dirname "$TEXTS_FILE")"

run() { echo; echo ">>> $*"; "$@"; }

# ── Phase 1: Generate attacks ─────────────────────────────────────────────────
echo "============================================================"
echo " Phase 1: Generating attacks for $REPO_NAME"
echo "============================================================"

if [ $# -gt 0 ]; then
    run python "$DEMO_DIR/attack_agent.py" \
        --repo "$TARGET_REPO" --target "$TARGET_FN" \
        --output "$TEXTS_FILE" --attack-type "$@"
    run python "$DEMO_DIR/build_attacks.py" \
        --texts "$TEXTS_FILE" --repo "$TARGET_REPO" --output "$ATTACKS_DIR" \
        --attack-type "$@"
else
    run python "$DEMO_DIR/attack_agent.py" \
        --repo "$TARGET_REPO" --target "$TARGET_FN" \
        --output "$TEXTS_FILE" --all-attacks
    run python "$DEMO_DIR/build_attacks.py" \
        --texts "$TEXTS_FILE" --repo "$TARGET_REPO" --output "$ATTACKS_DIR"
fi

# ── Phase 2: Baseline ─────────────────────────────────────────────────────────
echo
echo "============================================================"
echo " Phase 2: Baseline — both auditors on clean repo"
echo "============================================================"

echo "--- RepoAudit (baseline) ---"
cd "$RA_SRC"
RA_RESULT_ROOT="$RESULTS_DIR/repoaudit/baseline" \
LANGUAGE=Cpp MODEL="$RA_MODEL" \
    bash run_repoaudit.sh "$TARGET_REPO" NPD

echo
echo "--- VulnLLM-R (baseline) ---"
cd "$VL_DIR"
"$VL_PYTHON" -m agent_scaffold.scan \
    --repo "$TARGET_REPO" \
    --language c \
    --vllm "$VL_MODEL" \
    --policy-runs "$POLICY_RUNS" \
    --max-tokens "$MAX_TOKENS" \
    --cwe-hint CWE-476 \
    --target "$TARGET_FN" \
    --output "$RESULTS_DIR/vulnllm/baseline_vulnllm.json" \
    --verbose

# ── Phase 3: Post-attack ──────────────────────────────────────────────────────
echo
echo "============================================================"
echo " Phase 3: Post-attack — both auditors on each attacked repo"
echo "============================================================"

for attacked_dir in "$ATTACKS_DIR"/attacked_repo_*/; do
    [ -d "$attacked_dir" ] || continue
    name="$(basename "${attacked_dir%/}")"
    echo
    echo "--- $name ---"

    cd "$RA_SRC"
    RA_RESULT_ROOT="$RESULTS_DIR/repoaudit/$name" \
    LANGUAGE=Cpp MODEL="$RA_MODEL" \
        bash run_repoaudit.sh "$attacked_dir" NPD

    cd "$VL_DIR"
    "$VL_PYTHON" -m agent_scaffold.scan \
        --repo "$attacked_dir" \
        --language c \
        --vllm "$VL_MODEL" \
        --policy-runs "$POLICY_RUNS" \
        --max-tokens "$MAX_TOKENS" \
        --cwe-hint CWE-476 \
        --target "$TARGET_FN" \
        --output "$RESULTS_DIR/vulnllm/${name}_vulnllm.json"
done

# ── Phase 4: Compare ──────────────────────────────────────────────────────────
echo
echo "============================================================"
echo " Phase 4: Results comparison"
echo "============================================================"

python "$DEMO_DIR/compare_results.py" "$RESULTS_DIR"

echo
echo "=== Done. Launch viewer: python demo/viewer.py → http://localhost:6003 ==="
