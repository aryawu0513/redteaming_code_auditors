#!/usr/bin/env bash
# Run filter 1+2 and filter 3 end-to-end, then dedup.
# Output: f3_dedup.jsonl  (ready for VulnLLM-R / viewer)
#
# Usage:
#   cd /mnt/ssd/aryawu/redteaming_code_auditors
#   bash repo_cve_dataset_mining/run_filters.sh
#
# Set GITHUB_TOKEN for 5000 req/hr instead of 60:
#   GITHUB_TOKEN=ghp_... bash repo_cve_dataset_mining/run_filters.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOKEN="${GITHUB_TOKEN:-}"

echo "=== Clearing old candidates ==="
rm -f "$HERE"/candidates/*.json
echo "  done"
echo ""

echo "=== Filter 1+2: stream MegaVul CWE-476 (takes ~10 min) ==="
python "$HERE/filter_pipeline.py" \
    --filter12 --out "$HERE/f12.jsonl"

echo ""
echo "=== Filter 3: fetch files from GitHub (takes ~1-2 hr) ==="
if [ -n "$TOKEN" ]; then
    python "$HERE/filter_pipeline.py" \
        --filter3 --in "$HERE/f12.jsonl" --out "$HERE/f3.jsonl" \
        --token "$TOKEN"
else
    echo "  (no GITHUB_TOKEN — rate-limited to ~60 req/hr)"
    python "$HERE/filter_pipeline.py" \
        --filter3 --in "$HERE/f12.jsonl" --out "$HERE/f3.jsonl"
fi

echo ""
echo "=== Dedup: one per CVE (keeps most distinct bug per unique vulnerability) ==="
F3_IN="$HERE/f3.jsonl" F3_OUT="$HERE/f3_dedup.jsonl" python3 - <<'EOF'
import json, os
from pathlib import Path
from collections import defaultdict

rows = [json.loads(l) for l in Path(os.environ['F3_IN']).read_text().splitlines() if l.strip()]

# First pass: exact duplicates (same repo+file+func)
seen_exact = set()
unique = []
for r in rows:
    key = (r["repo_url"], r["file_path"], r["func_name"])
    if key not in seen_exact:
        seen_exact.add(key)
        unique.append(r)

# Second pass: one per CVE — pick entry with smallest full_file
# (prefer simpler files as context for the model)
by_cve = defaultdict(list)
for r in unique:
    by_cve[r["cve_id"]].append(r)

kept = []
for cve, entries in sorted(by_cve.items()):
    best = min(entries, key=lambda r: len(r.get("full_file", "")))
    kept.append(best)
    if len(entries) > 1:
        dropped = [e["func_name"] for e in entries if e is not best]
        print(f"  {cve}: kept {best['func_name']!r}, dropped {dropped}")

out = Path(os.environ['F3_OUT'])
out.write_text("\n".join(json.dumps(r) for r in kept) + "\n")
print(f"\nDedup: {len(rows)} raw → {len(unique)} exact-unique → {len(kept)} one-per-CVE → {out}")
EOF

echo ""
echo "=== Done. Eyeball in viewer: ==="
echo "  python $HERE/viewer.py --jsonl $HERE/f3_dedup.jsonl --port 8082"
echo ""
echo "=== Then run VulnLLM-R on all: ==="
echo "  python $HERE/test_vulnllmr.py $HERE/f3_dedup.jsonl"
