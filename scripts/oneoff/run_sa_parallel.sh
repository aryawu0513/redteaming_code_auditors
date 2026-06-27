#!/usr/bin/env bash
# Run CppCheck, Infer, and CodeQL SA coverage measurement in parallel.
# Each tool uses its own set of repo worktrees so they never conflict.
#
# Step 1: Set up git worktrees for Infer and CodeQL (fast, ~1 min).
# Step 2: Launch all three SA scripts in the background, logging to logs/.
# Step 3: Wait for all three to finish and print a summary.
#
# Usage:
#   bash scripts/run_sa_parallel.sh
#   bash scripts/run_sa_parallel.sh --resume   # skip already-done slugs
#
# Estimated runtime: CppCheck ~2-4h, Infer ~1-2h, CodeQL ~2-3h (in parallel)
# Logs: logs/sa_cppcheck.log, logs/sa_infer.log, logs/sa_codeql.log
# Results: results/sa_cppcheck.json, results/sa_infer.json, results/sa_codeql.json

set -e
cd "$(dirname "$0")/.."

RESUME="${1:-}"
LOG_DIR="logs"
mkdir -p "$LOG_DIR" results

echo "=== SA Parallel Run ==="
echo "Logs will be written to $LOG_DIR/"
echo ""

# ── Step 1: Set up worktrees ────────────────────────────────────────────────
INFER_MANIFEST="/mnt/ssd/aryawu/cve_repos_infer/clone_manifest.json"
CODEQL_MANIFEST="/mnt/ssd/aryawu/cve_repos_codeql/clone_manifest.json"

if [ ! -f "$INFER_MANIFEST" ] || [ ! -f "$CODEQL_MANIFEST" ]; then
    echo "[setup] Creating git worktrees for Infer and CodeQL repos..."
    python scripts/oneoff/sa_setup_worktrees.py
    echo "[setup] Done."
else
    echo "[setup] Worktrees already exist (manifests found), skipping setup."
    echo "        (Run: python scripts/oneoff/sa_setup_worktrees.py --remove  to rebuild)"
fi
echo ""

# ── Step 2: Launch all three in parallel ────────────────────────────────────
RESUME_FLAG=""
if [ "$RESUME" = "--resume" ]; then
    RESUME_FLAG="--resume"
    echo "[info] Resume mode: skipping already-completed slugs."
fi

echo "[launch] Starting CppCheck → $LOG_DIR/sa_cppcheck.log"
python scripts/oneoff/sa_cppcheck.py $RESUME_FLAG \
    > "$LOG_DIR/sa_cppcheck.log" 2>&1 &
PID_CPPCHECK=$!

echo "[launch] Starting Infer    → $LOG_DIR/sa_infer.log"
python scripts/oneoff/sa_infer.py $RESUME_FLAG \
    > "$LOG_DIR/sa_infer.log" 2>&1 &
PID_INFER=$!

echo "[launch] Starting CodeQL   → $LOG_DIR/sa_codeql.log"
python scripts/oneoff/sa_codeql.py $RESUME_FLAG \
    > "$LOG_DIR/sa_codeql.log" 2>&1 &
PID_CODEQL=$!

echo ""
echo "PIDs: cppcheck=$PID_CPPCHECK  infer=$PID_INFER  codeql=$PID_CODEQL"
echo "Monitor progress with:"
echo "  tail -f $LOG_DIR/sa_cppcheck.log"
echo "  tail -f $LOG_DIR/sa_infer.log"
echo "  tail -f $LOG_DIR/sa_codeql.log"
echo ""
echo "Waiting for all three to finish..."

# ── Step 3: Wait and summarize ───────────────────────────────────────────────
wait $PID_CPPCHECK; EC_CPPCHECK=$?
wait $PID_INFER;    EC_INFER=$?
wait $PID_CODEQL;   EC_CODEQL=$?

echo ""
echo "=== All done ==="
echo "Exit codes: cppcheck=$EC_CPPCHECK  infer=$EC_INFER  codeql=$EC_CODEQL"
echo ""

# Print final summaries from each log
for tool in cppcheck infer codeql; do
    echo "--- $tool ---"
    grep -A8 "^===" "$LOG_DIR/sa_${tool}.log" | tail -10 || echo "(no summary found)"
    echo ""
done

echo "Results:"
ls -lh results/sa_*.json 2>/dev/null || echo "  (no result files found)"
