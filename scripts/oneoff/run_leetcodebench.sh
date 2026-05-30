#!/usr/bin/env bash
# run_leetcodebench.sh — Run the LeetCode attacker benchmark on one system.
#
# Usage:
#   SYSTEM=vulnllm   bash scripts/run_leetcodebench.sh
#   SYSTEM=vultrial  bash scripts/run_leetcodebench.sh
#   SYSTEM=openvul   bash scripts/run_leetcodebench.sh
#   SYSTEM=repoaudit bash scripts/run_leetcodebench.sh
#
# Prerequisites and model overrides are the same as the corresponding
# run_*_c_npd.sh (e.g. VL_MODEL, VT_MODEL, OV_MODEL, MODEL, MODES).
#
# To run a single slug:
#   SYSTEM=vulnllm VARIANTS=repository_069A7F404506 bash scripts/run_leetcodebench.sh

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SYSTEM="${SYSTEM:-}"
if [[ -z "$SYSTEM" ]]; then
    echo "Usage: SYSTEM=vulnllm|vultrial|openvul|repoaudit bash $0" >&2
    exit 1
fi

export DATASET_ROOT="${DATASET_ROOT:-$REPO_ROOT/benchmark/leetcodebench_gpt54mini}"
export VARIANTS="${VARIANTS:-repository_069A7F404506 repository_3FC486D0AE27 repository_6961F2970560 repository_6B249C5786A8 repository_7C95B6A69704 repository_9823AA10FA1B repository_A3BC94AC32E5 repository_B1AC850C7E87}"

case "$SYSTEM" in
    vulnllm)   bash "$REPO_ROOT/scripts/run_vulnllm_c_npd.sh"  ;;
    vultrial)  bash "$REPO_ROOT/scripts/run_vultrial_c_npd.sh" ;;
    openvul)   bash "$REPO_ROOT/scripts/run_openvul_c_npd.sh"  ;;
    repoaudit) bash "$REPO_ROOT/scripts/run_repoaudit_c_npd.sh" ;;
    *) echo "Unknown system: $SYSTEM (use vulnllm|vultrial|openvul|repoaudit)" >&2; exit 1 ;;
esac
