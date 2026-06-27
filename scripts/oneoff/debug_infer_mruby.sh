#!/usr/bin/env bash
# Debug: run bear + Infer on NPD-CVE-0653 (mruby, mrb_ary_shift_m)
set -e

REPO="/mnt/ssd/aryawu/cve_repos_infer/mruby__mruby__27d1e0132a"
TARGET_FILE="$REPO/src/array.c"
INFER="/mnt/ssd/aryawu/infer-linux64-v1.1.0/bin/infer"
OUT="/tmp/debug_infer_mruby"

LAYER="/mnt/ssd/aryawu/.local/share/containers/storage/overlay/25a38ed902c37561c38cd13b726fc94ab7e643c1a5e27dd8287e8639fde067db/diff"
BEAR="$LAYER/usr/bin/bear"
BEAR_LD="$LAYER/usr/lib/x86_64-linux-gnu:$LAYER/usr/lib/x86_64-linux-gnu/bear"

echo "=== Step 1: bear -- make -B to generate compile_commands.json ==="
cd "$REPO"
LD_LIBRARY_PATH="$BEAR_LD" \
    "$BEAR" \
    --interceptor "$LAYER/usr/bin/intercept" \
    --library     "$LAYER/usr/lib/x86_64-linux-gnu/bear/libexec.so" \
    --citnames    "$LAYER/usr/bin/citnames" \
    --wrapper     "$LAYER/usr/lib/x86_64-linux-gnu/bear/wrapper" \
    --wrapper-dir "$LAYER/usr/lib/x86_64-linux-gnu/bear/wrapper.d" \
    -- make -B -j4 -k || true

if [ ! -f "$REPO/compile_commands.json" ]; then
    echo "ERROR: compile_commands.json not generated"
    exit 1
fi
echo "compile_commands.json entries: $(python3 -c "import json; print(len(json.load(open('$REPO/compile_commands.json'))))")"

echo ""
echo "=== Step 2: run Infer ==="
rm -rf "$OUT"
"$INFER" run \
    --compilation-database "$REPO/compile_commands.json" \
    --keep-going \
    --results-dir "$OUT"

echo ""
echo "=== Step 3: check for NULL_DEREFERENCE in mrb_ary_shift_m ==="
python3 - <<'EOF'
import json
from pathlib import Path

report = json.loads(Path("/tmp/debug_infer_mruby/report.json").read_text())
null_hits = [r for r in report if r.get("bug_type","") in ("NULL_DEREFERENCE","NULLPTR_DEREFERENCE")]
print(f"Total NULL_DEREFERENCE bugs: {len(null_hits)}")
print(f"In mrb_ary_shift_m: {sum(1 for r in null_hits if r.get('procedure') == 'mrb_ary_shift_m')}")
print(f"In src/array.c: {sum(1 for r in null_hits if 'array.c' in r.get('file',''))}")
print()
for r in null_hits:
    if 'array.c' in r.get('file','') or r.get('procedure') == 'mrb_ary_shift_m':
        print(f"  {r.get('procedure')}  line {r.get('line')}  {r.get('qualifier','')[:80]}")
EOF
