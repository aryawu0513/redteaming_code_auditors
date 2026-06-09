#!/usr/bin/env bash
# run_fromscratch_new_cve.sh
#
# From-scratch adaptive attack on the new CVE NPD samples (NPD-CVE-0020 …)
# against VulnLLM-R.
#
# Requires:
#   - VulnLLM-R served at $DETECTOR_URL  (default: http://localhost:8008)
#   - Qwen refiner served at $OPENAI_BASE_URL (default: http://localhost:8007/v1)
#   - OPENAI_API_KEY set (can be "dummy" if server doesn't check)
#
# Step 1 (baseline probe only):
#   Runs probe_cve_new_vulnllmr.py — checks VulnLLM-R detection + F5 on context.cc.
#   No Qwen needed.
#
# Step 2 (full adaptive attack):
#   Sets up attacker run dirs, then launches refine_loop_fromscratch.py.
#   Needs both VulnLLM-R and Qwen.
#
# Usage:
#   STEP=1 bash scripts/oneoff/run_fromscratch_new_cve.sh      # probe only
#   STEP=2 bash scripts/oneoff/run_fromscratch_new_cve.sh      # full attack
#   bash scripts/oneoff/run_fromscratch_new_cve.sh             # both steps

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SAMPLES_DIR="$REPO_ROOT/repo_cve_dataset_mining/samples_ts_full"
JSONL="$REPO_ROOT/repo_cve_dataset_mining/f3_nolimit_dedup_func.jsonl"

DETECTOR_URL="${DETECTOR_URL:-http://localhost:8008}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://localhost:8007/v1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
REFINER_MODEL="${REFINER_MODEL:-Qwen/Qwen3.6-27B-FP8}"
BUDGET="${BUDGET:-5}"
RUN_TAG="${RUN_TAG:-fromscratch_v1}"
STEP="${STEP:-}"  # 1=probe, 2=attack, empty=both

# The 7 validated new samples + NPD-CVE-0009 (auxiliary.cc verification test)
SLUGS=(
    NPD-CVE-0020
    NPD-CVE-0051
    NPD-CVE-0211
    NPD-CVE-0216
    NPD-CVE-0263
    NPD-CVE-0273
    NPD-CVE-0282
    NPD-CVE-0009   # has auxiliary.cc — tests that detector sees cross-file helpers
)

# Slugs with validated task.md + tests.cc (can run full adaptive attack)
ATTACK_SLUGS=(
    NPD-CVE-0020
    NPD-CVE-0051
    NPD-CVE-0211
    NPD-CVE-0216
    NPD-CVE-0263
    NPD-CVE-0273
    NPD-CVE-0282
)

echo "================================================================"
echo " CVE new-sample adaptive attack  (${#SLUGS[@]} slugs)"
echo " Detector:       $DETECTOR_URL"
echo " Refiner:        $OPENAI_BASE_URL  ($REFINER_MODEL)"
echo " Samples dir:    $SAMPLES_DIR"
echo "================================================================"
echo ""

# ── Step 1: probe VulnLLM-R on context.cc ────────────────────────────────────
if [[ -z "$STEP" || "$STEP" == "1" ]]; then
    echo "=== STEP 1: VulnLLM-R baseline probe ==="
    python3 "$REPO_ROOT/scripts/oneoff/probe_cve_new_vulnllmr.py" \
        --detector-url "$DETECTOR_URL" \
        --out /tmp/cve_new_probe_results.jsonl \
        "${SLUGS[@]}"
    echo ""
    echo "Probe results saved to /tmp/cve_new_probe_results.jsonl"
    echo ""
fi

# ── Step 2: full from-scratch adaptive attack ─────────────────────────────────
if [[ -z "$STEP" || "$STEP" == "2" ]]; then
    echo "=== STEP 2: from-scratch adaptive attack ==="

    # Build per-slug baseline CLEAN.json files if not already present
    echo "--- Creating baseline CLEAN.json records ---"
    python3 - <<'PYEOF'
import json
import re
import sys
from pathlib import Path

REPO_ROOT   = Path(__file__).parent.parent.parent if False else Path(".")
SAMPLES_DIR = REPO_ROOT / "repo_cve_dataset_mining" / "samples_ts_full"
BENCH_DIR   = REPO_ROOT / "benchmark" / "cvebench_new" / "baseline"

ATTACK_SLUGS = [
    "NPD-CVE-0020", "NPD-CVE-0051", "NPD-CVE-0211", "NPD-CVE-0216",
    "NPD-CVE-0263", "NPD-CVE-0273", "NPD-CVE-0282",
]

def split_at_function(src, func_name, lang):
    from tree_sitter import Language, Parser
    import tree_sitter_c, tree_sitter_cpp
    ts_lang = Language(tree_sitter_cpp.language() if lang == "cpp" else tree_sitter_c.language())
    parser  = Parser(ts_lang)
    src_bytes = src.encode("utf-8")
    tree = parser.parse(src_bytes)

    def node_text(n):
        return src_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")

    def get_name(node):
        for child in node.children:
            if child.type in ("function_declarator", "pointer_declarator", "reference_declarator"):
                return get_name(child)
            if child.type in ("identifier", "field_identifier", "qualified_identifier",
                               "destructor_name", "operator_name"):
                return node_text(child).split("::")[-1]
        return None

    def walk(node):
        if node.type == "function_definition":
            for child in node.children:
                if "declarator" in child.type:
                    name = get_name(child)
                    if name == func_name:
                        pre  = src_bytes[:node.start_byte].decode("utf-8", errors="replace").rstrip()
                        body = src_bytes[node.start_byte:].decode("utf-8", errors="replace")
                        return pre, body
                    break
        for child in node.children:
            r = walk(child)
            if r: return r
        return None

    return walk(tree.root_node)

for slug in ATTACK_SLUGS:
    sample_dir = SAMPLES_DIR / slug
    out_dir    = BENCH_DIR / f"repository_{slug}"
    out_file   = out_dir / f"{slug}_CLEAN.json"

    if out_file.exists():
        print(f"  {slug}: already exists — skip")
        continue

    meta      = json.loads((sample_dir / "metadata.json").read_text())
    func_name = meta.get("function", meta.get("func_name", ""))
    lang      = meta.get("lang", "c")
    src       = (sample_dir / "context.cc").read_text()

    split = split_at_function(src, func_name, lang) if func_name else None
    if split:
        ctx, tf = split
    else:
        print(f"  {slug}: WARNING — could not find {func_name!r}, using full file")
        ctx, tf = "", src

    record = [{
        "code":            "// context\n" + ctx + "\n\n" + tf,
        "context":         ctx,
        "target_function": tf,
        "function_name":   func_name,
        "deref_line":      "",
        "caller":          func_name,
        "file_name":       "context.cc",
        "CWE_ID":          ["CWE-476"],
        "RELATED_CWE":     [],
        "stack_trace":     "",
        "target":          1,
        "language":        lang,
        "dataset":         "cvebench-npd",
        "idx":             0,
        "slug":            slug,
        "variant":         "CLEAN",
    }]

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(record, indent=2))
    # also copy context.cc as solution.cc for consistency
    import shutil
    shutil.copy(sample_dir / "context.cc", out_dir / "solution.cc")
    print(f"  {slug}: created ({func_name}, {lang})")

print("Done.")
PYEOF

    # Run from-scratch attacker on each slug
    DATASET="$REPO_ROOT/benchmark/cvebench_new/context_aware"
    SCRIPT="$REPO_ROOT/attacker/adaptive/refine_loop_fromscratch.py"

    for slug in "${ATTACK_SLUGS[@]}"; do
        echo ""
        echo "========================================"
        echo "  slug: $slug"
        echo "========================================"
        python3 "$SCRIPT" \
            --slug         "$slug" \
            --dataset      "$DATASET" \
            --detector-url "$DETECTOR_URL" \
            --system       vulnllmr_fromscratch \
            --refiner-model "$REFINER_MODEL" \
            --refiner-temperature 1.0 \
            --budget       "$BUDGET" \
            --run-tag      "$RUN_TAG"
    done

    echo ""
    echo "All slugs done. Results in attacker/adaptive/results/vulnllmr_fromscratch/"
fi
