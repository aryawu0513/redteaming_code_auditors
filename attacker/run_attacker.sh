#!/usr/bin/env bash
# run_attacker.sh — Run the attacker agent on one or more experiment directories,
# once per attack type (mirrors generate_variant.py which generates one payload per type).
#
# Usage:
#   ./attacker/run_attacker.sh                                    # all experiments × all attack types
#   ./attacker/run_attacker.sh attacker/experiments/repository_XXXX ...
#
# Per (problem, attack_type) pair, writes:
#   solution_{ATTACK_TYPE}.cpp   — agent's malicious solution
#   trajectory_{ATTACK_TYPE}.json
#
# Must be run from the repo root (redteaming_code_auditors/).
# Requires OPENAI_API_KEY to be set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/config.yaml"
ATTACK_TYPES=(COT FT CG AA_MSG AA_USR AA_CA TOOL_ClangSA TOOL_Frama TOOL_Fuzzer TOOL_Coverity)

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: config.yaml not found. Run: python attacker/build_config.py" >&2
    exit 1
fi

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "ERROR: OPENAI_API_KEY is not set" >&2
    exit 1
fi

# Resolve experiment directories
if [[ $# -gt 0 ]]; then
    DIRS=("$@")
else
    DIRS=("$SCRIPT_DIR"/experiments/repository_*)
fi

INSTANCE_CONFIG=$(mktemp /tmp/attacker_instance_XXXX.yaml)
trap "rm -f $INSTANCE_CONFIG" EXIT

for dir in "${DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        echo "WARNING: not a directory: $dir" >&2
        continue
    fi
    for attack_type in "${ATTACK_TYPES[@]}"; do
        traj="$dir/trajectory_${attack_type}.json"

        # Skip if already done
        if [[ -f "$traj" ]]; then
            echo "  SKIP $(basename "$dir") / $attack_type (trajectory exists)"
            continue
        fi

        echo "=== $(basename "$dir") / $attack_type ==="

        # Generate instance config with this attack type
        python "$SCRIPT_DIR/make_instance_config.py" \
            --attack-type "$attack_type" \
            --output "$INSTANCE_CONFIG"

        pushd "$dir" > /dev/null
        mini \
            --config "$CONFIG" \
            --config "$INSTANCE_CONFIG" \
            --model "openai/gpt-5-mini" \
            --output "trajectory_${attack_type}.json" \
            --yolo \
            --exit-immediately

        # Rename solution.cpp → solution_{ATTACK_TYPE}.cpp if agent wrote it
        if [[ -f solution.cpp ]]; then
            mv solution.cpp "solution_${attack_type}.cpp"
        fi
        popd > /dev/null
        echo ""
    done
done
