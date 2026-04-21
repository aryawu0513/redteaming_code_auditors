#!/usr/bin/env bash
# clean_and_regenerate.sh — Remove DPI + retired attacks, regenerate benchmark from scratch.
#
# Run once to purge all DPI and AA_PR/TOOL_MISRA/TOOL_Pylint artifacts, then
# regenerate RepoAudit/benchmark/ and VulnLLM-R/datasets/ cleanly with the
# 10 canonical context-aware attacks only.
#
# Prerequisites:
#   source .venv/bin/activate
#   export ANTHROPIC_API_KEY=...   (not needed here — no LLM calls)
#
# This script is safe to re-run.

set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== 1. Removing DPI directories ==="
for subtree in C/NPD C/UAF Python/NPD; do
    for sys in RepoAudit/benchmark VulnLLM-R/datasets; do
        target="$REPO/$sys/$subtree/dpi"
        if [ -d "$target" ]; then
            rm -rf "$target"
            echo "  deleted $sys/$subtree/dpi"
        fi
    done
done

echo
echo "=== 2. Removing context_aware directories (will regenerate cleanly) ==="
for subtree in C/NPD C/UAF Python/NPD; do
    for sys in RepoAudit/benchmark VulnLLM-R/datasets; do
        target="$REPO/$sys/$subtree/context_aware"
        if [ -d "$target" ]; then
            rm -rf "$target"
            echo "  deleted $sys/$subtree/context_aware"
        fi
    done
done

echo
echo "=== 3. Removing demo attacked repos for AA_PR / TOOL_MISRA ==="
for repo in target_repo target_repo_v2; do
    attacks_dir="$REPO/demo/${repo}_attacks"
    [ -d "$attacks_dir" ] || continue
    for name in attacked_repo_AA_PR attacked_repo_TOOL_MISRA; do
        target="$attacks_dir/$name"
        if [ -d "$target" ]; then
            rm -rf "$target"
            echo "  deleted demo/${repo}_attacks/$name"
        fi
    done
done

echo
echo "=== 4. Removing demo results for AA_PR / TOOL_MISRA ==="
for repo in target_repo target_repo_v2; do
    results_dir="$REPO/demo/results/$repo"
    [ -d "$results_dir" ] || continue
    find "$results_dir" -type d \( -name "attacked_repo_AA_PR" -o -name "attacked_repo_TOOL_MISRA" \) \
        -print -exec rm -rf {} + 2>/dev/null || true
done

echo
echo "=== 5. Scrubbing AA_PR / TOOL_MISRA from demo JSON files ==="
REPO="$REPO" python3 - <<'PYEOF'
import json, os, re

REPO = os.environ['REPO']
REMOVE = {'AA_PR', 'TOOL_MISRA', 'TOOL_Pylint'}

def scrub_json_keys(path, key_filter):
    """Remove top-level keys matching key_filter from a JSON object file."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        data = json.load(f)
    before = len(data)
    data = {k: v for k, v in data.items() if not key_filter(k)}
    after = len(data)
    if before != after:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  {os.path.relpath(path, REPO)}: removed {before - after} entries")
    else:
        print(f"  {os.path.relpath(path, REPO)}: nothing to remove")

# demo/texts/demo*.json  — remove attack-type keys
for fname in ['demo.json', 'demo_v2.json']:
    p = os.path.join(REPO, 'demo', 'texts', fname)
    if os.path.exists(p):
        with open(p) as f:
            data = json.load(f)
        changed = False
        for vname in list(data.keys()):
            for bad in REMOVE:
                if bad in data[vname]:
                    del data[vname][bad]
                    changed = True
        if changed:
            with open(p, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"  demo/texts/{fname}: removed retired attack keys")
        else:
            print(f"  demo/texts/{fname}: nothing to remove")

# highlight_cache*.json — remove keys like "target_repo:AA_PR:repoaudit"
for fname in ['highlight_cache.json', 'highlight_cache_defense.json']:
    p = os.path.join(REPO, 'demo', fname)
    scrub_json_keys(p, lambda k: any(f':{bad}:' in k for bad in REMOVE))

PYEOF

echo
echo "=== 6. Regenerating context_aware benchmark (10 attacks) ==="
cd "$REPO"
python automatic/gen_attacks.py --bug-type npd --language c
python automatic/gen_attacks.py --bug-type uaf --language c
python automatic/gen_attacks.py --bug-type npd --language python

echo
echo "=== Done. ==="
echo "  - dpi/ removed everywhere"
echo "  - context_aware/ regenerated with 10 canonical attacks"
echo "  - demo attack dirs / results / JSON caches scrubbed"
