#!/usr/bin/env bash
# setup_benchmark.sh — Populate RepoAudit/benchmark/ and VulnLLM-R/datasets/ from
#                      benchmark/ safe codes and automatic/texts/ attack payloads.
#
# Run this once after cloning the repo, then use run_repoaudit_c_npd.sh etc.
#
# To add a new variant:
#   1. Add safe code to benchmark/{lang}/{bug}/safe/{variant}/
#   2. Run generate_variant.py to produce automatic/texts/ entry
#   3. Re-run this script (existing files are overwritten)
#
# Prerequisites: source RepoAudit/.venv/bin/activate

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Populating RepoAudit/benchmark/ from benchmark/ safe codes ==="
for LANG_BUG in C/NPD C/UAF Python/NPD; do
    SRC="$REPO_ROOT/benchmark/$LANG_BUG/safe"
    DST="$REPO_ROOT/RepoAudit/benchmark/$LANG_BUG/safe"
    [ -d "$SRC" ] || continue
    mkdir -p "$DST"
    rsync -a "$SRC/" "$DST/"
    echo "  Copied $LANG_BUG/safe → RepoAudit/benchmark/$LANG_BUG/safe/"
done

echo
echo "=== Extracting buggy baselines from automatic/texts/ ==="
REPO_ROOT="$REPO_ROOT" python3 - <<'PYEOF'
import json, os
REPO = os.environ['REPO_ROOT']

configs = [
    ('c',      'npd', 'C',      'NPD', 'c'),
    ('c',      'uaf', 'C',      'UAF', 'c'),
    ('python', 'npd', 'Python', 'NPD', 'py'),
]
for lang, bug, Lang, Bug, ext in configs:
    src_file = f'{REPO}/automatic/texts/{lang}_{bug}.json'
    if not os.path.exists(src_file):
        print(f'  [skip] {src_file} not found')
        continue
    texts = json.load(open(src_file))
    for vname, vdata in texts.items():
        meta = vdata.get('meta', {})
        code = meta.get('clean_code', '')
        if not code:
            continue
        d = f'{REPO}/RepoAudit/benchmark/{Lang}/{Bug}/buggy/{vname}'
        os.makedirs(d, exist_ok=True)
        dest = f'{d}/{vname}_clean.{ext}'
        with open(dest, 'w') as f:
            f.write(code)
    print(f'  {Lang}/{Bug}: buggy baselines extracted')
PYEOF

echo
echo "=== Running gen_attacks.py to generate context-aware attack files ==="
cd "$REPO_ROOT"
python automatic/gen_attacks.py --bug-type npd --language c
python automatic/gen_attacks.py --bug-type uaf --language c
python automatic/gen_attacks.py --bug-type npd --language python

echo
echo "=== Done. Benchmark populated in RepoAudit/benchmark/ and VulnLLM-R/datasets/ ==="
