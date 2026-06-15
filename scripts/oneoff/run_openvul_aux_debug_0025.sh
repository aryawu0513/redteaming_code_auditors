#!/usr/bin/env bash
# run_openvul_aux_debug_0025.sh
#
# Runs the full adaptive attack on NPD-CVE-0025 against OpenVul three times,
# each with a different auxiliary ordering in the context window:
#
#   no_aux    — context_before + context_after only
#   aux_first — auxiliary_file + context_before + context_after  (current default)
#   aux_last  — context_before + context_after + auxiliary_file
#
# Context is pre-assembled into context_before in a temp baseline dir so that
# detector_openvul._build_prompt sees a single pre-built block (auxiliary_file
# and context_after are zeroed). This tests ordering without modifying detector code.
#
# Requires:
#   - OpenVul served at $DETECTOR_URL (default http://localhost:8009)
#     Run: ./scripts/serve_detector_openvul.sh
#   - Qwen refiner at $OPENAI_BASE_URL (default http://localhost:8007/v1)
#
# Results land in:
#   adaptive_attacker/results/openvul_aux_debug_{variant}/repository_NPD-CVE-0025/

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8009}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
SLUG="NPD-CVE-0025"
ORIG_BASELINE="$REPO_ROOT/benchmark/cvebench_full/baseline/repository_${SLUG}"
RECORD_FILE="${SLUG}_CLEAN.json"

TMPDIR_ROOT="$(mktemp -d /tmp/openvul_aux_debug_XXXX)"
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

# Build a modified baseline dir with pre-assembled context.
# load_baseline_record() in refine_loop_fromscratch.py resolves the baseline as
#   DATASET_DIR.parent / "baseline" / f"repository_{slug}"
# so when --dataset points to X/baseline, parent/baseline == X/baseline (same dir).
# We replicate that structure: $TMPDIR_ROOT/$variant/baseline/repository_$SLUG/
make_variant() {
    local variant="$1"
    local out_dir="$TMPDIR_ROOT/$variant/baseline/repository_${SLUG}"
    mkdir -p "$out_dir"

    python3 - "$ORIG_BASELINE/$RECORD_FILE" "$out_dir/$RECORD_FILE" "$variant" <<'PYEOF'
import json, sys

src, dst, variant = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.loads(open(src).read())
rec = data[0] if isinstance(data, list) else data

aux    = rec.get("auxiliary_file", "").strip()
before = rec.get("context_before", "").strip()
after  = rec.get("context_after",  "").strip()

SEP = "\n\n"
if variant == "no_aux":
    assembled = SEP.join(p for p in [before, after] if p)
elif variant == "aux_first":
    assembled = SEP.join(p for p in [aux, before, after] if p)
elif variant == "aux_last":
    assembled = SEP.join(p for p in [before, after, aux] if p)
else:
    raise ValueError(f"unknown variant: {variant}")

modified = {
    **rec,
    "context_before":  assembled,
    "context_after":   "",
    "auxiliary_file":  "",
}
out = [modified] if isinstance(data, list) else modified
open(dst, "w").write(json.dumps(out, indent=2))
print(f"[aux_debug] variant={variant}  context_before={len(assembled)} chars", file=__import__("sys").stderr)
PYEOF

    echo "$TMPDIR_ROOT/$variant/baseline"   # this is the --dataset arg
}

SCRIPT="$REPO_ROOT/adaptive_attacker/refine_loop_fromscratch.py"

for variant in no_aux aux_first aux_last; do
    echo ""
    echo "========================================"
    echo "  variant: $variant"
    echo "========================================"
    baseline_root="$(make_variant "$variant")"

    python "$SCRIPT" \
        --slug                "$SLUG" \
        --dataset             "$baseline_root" \
        --detector-url        "$DETECTOR_URL" \
        --system              "openvul_aux_debug_${variant}" \
        --refiner-model       "$REFINER_MODEL" \
        --refiner-temperature 1.0 \
        --budget              "$BUDGET" \
        --run-tag             "aux_debug"
done

echo ""
echo "Done. Results in:"
for variant in no_aux aux_first aux_last; do
    echo "  adaptive_attacker/results/openvul_aux_debug_${variant}/repository_${SLUG}/"
done
