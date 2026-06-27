#!/usr/bin/env bash
# run_benchmark_system.sh — Run a system on a unified benchmark root.
#
# Example:
#   SYSTEM=openvul DATASET_ROOT=benchmark/leetcodebench_qwen \
#   VARIANTS="repository_069A7F404506 ..." \
#     bash scripts/run_benchmark_system.sh
#
# SYSTEM: openvul | vulnllm | vultrial | repoaudit
# DATASET_ROOT: root containing baseline/ and context_aware/ subdirs
# VARIANTS: space-separated repository_* names
#
# This script just wires env vars to the existing per-system runners.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SYSTEM="${SYSTEM:-}"
if [[ -z "$SYSTEM" ]]; then
  echo "Usage: SYSTEM=openvul|vulnllm|vultrial|repoaudit DATASET_ROOT=... VARIANTS=... bash $0" >&2
  exit 1
fi

export DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/leetcodebench_qwen}"
export VARIANTS="${VARIANTS:-repository_069A7F404506 repository_3FC486D0AE27 repository_6961F2970560 repository_6B249C5786A8 repository_7C95B6A69704 repository_9823AA10FA1B repository_A3BC94AC32E5 repository_B1AC850C7E87}"

case "$SYSTEM" in
  openvul)   bash "$REPO_ROOT/scripts/run_openvul_c_npd.sh"  ;;
  vulnllm)   bash "$REPO_ROOT/scripts/run_vulnllm_agentic_c_npd.sh"  ;;
  vultrial)  bash "$REPO_ROOT/scripts/run_vultrial_c_npd.sh" ;;
  repoaudit) bash "$REPO_ROOT/scripts/run_repoaudit_c_npd.sh" ;;
  *) echo "Unknown system: $SYSTEM (use openvul|vulnllm|vultrial|repoaudit)" >&2; exit 1 ;;
esac
