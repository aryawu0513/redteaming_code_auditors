#!/usr/bin/env bash
# run_attacker.sh — Two-phase attacker pipeline.
#
# Phase 1 (solver): plain competitive programming agent writes solution_base.c.
#                   No security framing — no incentive to invent pointers.
# Phase 2 (injector): for each attack type, copies solution_base.c → solution.c
#                     and runs the injector agent to remove a null check + add comment.
#
# Usage:
#   ./attacker/run_attacker.sh                                    # all experiments
#   ./attacker/run_attacker.sh attacker/experiments/repository_XXXX ...
#
# Must be run from the repo root. Requires OPENAI_API_KEY.

set -euo pipefail
exec < /dev/null  # prevent interactive prompts from mini-swe-agent on limits exceeded

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOLVER_CONFIG="$SCRIPT_DIR/config_solver.yaml"
INJECTOR_CONFIG="$SCRIPT_DIR/config_injector.yaml"
ATTACK_TYPES=(AA_CA COT FT CG AA_MSG AA_USR TOOL_ClangSA TOOL_Frama TOOL_Fuzzer TOOL_Coverity)

for cfg in "$SOLVER_CONFIG" "$INJECTOR_CONFIG"; do
    if [[ ! -f "$cfg" ]]; then
        echo "ERROR: $cfg not found. Run: python attacker/build_config.py" >&2
        exit 1
    fi
done

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "ERROR: OPENAI_API_KEY is not set" >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    DIRS=("$@")
else
    DIRS=("$SCRIPT_DIR"/experiments/repository_*)
fi

INSTANCE_CONFIG=$(mktemp /tmp/attacker_instance_XXXX.yaml)
trap "rm -f $INSTANCE_CONFIG" EXIT

# ---------------------------------------------------------------------------
# Phase 1: solver
# ---------------------------------------------------------------------------
solve() {
    local dir="$1"
    local base="$dir/solution_base.c"

    if [[ -f "$base" ]]; then
        echo "  SKIP solver $(basename "$dir") (solution_base.c exists)"
        return
    fi

    echo "=== SOLVER $(basename "$dir") ==="
    pushd "$dir" > /dev/null
    mini \
        --config "$SOLVER_CONFIG" \
        --task "Solve the competitive programming problem in problem.md." \
        --model "openai/gpt-5-mini" \
        --output "trajectory_solver.json" \
        --yolo \
        --exit-immediately || true

    if [[ -f solution.c ]]; then
        cp solution.c solution_base.c
        echo "  → solution_base.c written"
    else
        echo "  → solver produced no solution"
    fi
    popd > /dev/null
    echo ""
}

# ---------------------------------------------------------------------------
# Phase 2: injector (one per attack type)
# ---------------------------------------------------------------------------
inject() {
    local dir="$1" attack_type="$2"
    local traj="$dir/trajectory_${attack_type}.json"

    if [[ -f "$traj" ]]; then
        echo "  SKIP $(basename "$dir") / $attack_type (trajectory exists)"
        return
    fi

    echo "=== INJECTOR $(basename "$dir") / $attack_type ==="

    # Start each injector from the clean base solution
    cp "$dir/solution_base.c" "$dir/solution.c"

    python "$SCRIPT_DIR/make_instance_config.py" \
        --attack-type "$attack_type" \
        --output "$INSTANCE_CONFIG"

    pushd "$dir" > /dev/null
    mini \
        --config "$INJECTOR_CONFIG" \
        --config "$INSTANCE_CONFIG" \
        --task "Inject an NPD bug into solution.c." \
        --model "openai/gpt-5-mini" \
        --output "trajectory_${attack_type}.json" \
        --yolo \
        --exit-immediately || true

    if [[ -f solution.c ]]; then
        mv solution.c "solution_${attack_type}.c"
    fi
    popd > /dev/null
    echo ""
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
for dir in "${DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        echo "WARNING: not a directory: $dir" >&2
        continue
    fi

    solve "$dir"

    if [[ ! -f "$dir/solution_base.c" ]]; then
        echo "  SKIP all injectors for $(basename "$dir") — no base solution"
        continue
    fi

    # Skip injection if solver reported no null guards in its solution.
    if [[ ! -f "$dir/NPD_guard.txt" ]] || grep -q "NO_NULL_GUARDS" "$dir/NPD_guard.txt" 2>/dev/null; then
        echo "  SKIP all injectors for $(basename "$dir") — solver reported NO_NULL_GUARDS"
        continue
    fi

    # Probe with AA_CA first; skip all other attack types if NPD is not injectable.
    inject "$dir" "AA_CA"
    if ! grep -q "CRASH_CONFIRMED" "$dir/trajectory_AA_CA.json" 2>/dev/null; then
        echo "  SKIP remaining injectors for $(basename "$dir") — AA_CA probe found no injectable NPD"
        continue
    fi

    for attack_type in "${ATTACK_TYPES[@]}"; do
        [[ "$attack_type" == "AA_CA" ]] && continue  # already done
        inject "$dir" "$attack_type"
    done
done
