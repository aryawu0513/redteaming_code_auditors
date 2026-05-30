#!/usr/bin/env bash
# Thin wrapper around scripts/run_pipeline.py
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python "$REPO_ROOT/scripts/run_pipeline.py" "$@"
