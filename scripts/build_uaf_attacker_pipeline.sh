#!/usr/bin/env bash
# build_uaf_attacker_pipeline.sh — Task2 pipeline for the UAF benchmark:
# extract context -> generate task spec/stub -> attacker implements the bug
# -> verify (compile + run real test suite). Mirrors the NPD flow, using the
# 161 pass/partial UAF candidates from cvebench/samples_cve_uaf/ (written by
# check_repo_testsuite.py) as the viable set.
#
# Stages 1 auto-restrict to samples with a repo_testsuite_pass/partial
# sentinel already on disk — you do not need to pre-filter pilot IDs.
#
# Prerequisites (not checked by this script):
#   - Stage 2 (generate_task_only.py) calls OpenAI() directly (gpt-5-mini
#     default) -> needs a real OPENAI_API_KEY in the environment.
#   - Stage 3 (generate_attacker.py) defaults to a local Qwen server at
#     http://localhost:8007/v1 -> start that server first, or override
#     --model/--base-url below to point at whatever you have running.
#
# Usage:
#   bash scripts/build_uaf_attacker_pipeline.sh [stage]
#   stage: extract | headers | task | attack | verify | all (default: all)
#
# Re-running a stage is safe without --force: each stage skips samples that
# already have their output artifact on disk (raw_primary.cc / task.md /
# attacker_output.cc / verification result respectively).

set -euo pipefail
cd "$(dirname "$0")/.."

STAGE="${1:-all}"

JSONL="cvebench/f3_uaf_ids.jsonl"
SAMPLES_DIR="cvebench/samples_cve_uaf"
CLONE_DIR="/tmp/cve_repos_uaf"
PATCH_CLONE_DIR="/tmp/cve_patch_scratch_uaf"
ATTACKER_CONFIG="cvebench/config_cve_attacker_uaf.yaml"

run_extract() {
  echo "=== Stage 1: extract_context_cve.py (tree-sitter context extraction) ==="
  python3 cvebench/extract_context_cve.py "$JSONL" \
      --samples-dir "$SAMPLES_DIR" \
      --clone-dir "$CLONE_DIR" \
      --workers 4
}

run_headers() {
  echo "=== Stage 1b: extract_headers.py (project-local #include headers -> raw_headers.h) ==="
  python3 cvebench/extract_headers.py "$JSONL" \
      --samples-dir "$SAMPLES_DIR" \
      --clone-dir "$CLONE_DIR"
}

run_task() {
  echo "=== Stage 2: generate_task_only.py (task.md + starter.cc; needs OPENAI_API_KEY) ==="
  python3 cvebench/generate_task_only.py "$JSONL" \
      --samples-dir "$SAMPLES_DIR" \
      --source-dir "$SAMPLES_DIR" \
      --clone-dir "$CLONE_DIR" \
      --workers 4
}

run_attack() {
  echo "=== Stage 3: generate_attacker.py (implements the stub with a deliberate UAF; needs local model server) ==="
  python3 cvebench/generate_attacker.py "$JSONL" \
      --samples-dir "$SAMPLES_DIR" \
      --config "$ATTACKER_CONFIG" \
      --workers 4
}

run_verify() {
  echo "=== Stage 4: patch_and_test.py (splice attacker output, compile + run real test suite) ==="
  python3 cvebench/patch_and_test.py "$JSONL" \
      --samples-dir "$SAMPLES_DIR" \
      --clone-dir "$PATCH_CLONE_DIR"
}

case "$STAGE" in
  extract) run_extract ;;
  headers) run_headers ;;
  task)    run_task ;;
  attack)  run_attack ;;
  verify)  run_verify ;;
  all)
    run_extract
    echo
    run_headers
    echo
    run_task
    echo
    run_attack
    echo
    run_verify
    ;;
  *)
    echo "Unknown stage: $STAGE (expected extract|headers|task|attack|verify|all)" >&2
    exit 1
    ;;
esac
