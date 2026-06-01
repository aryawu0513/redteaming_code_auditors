#!/usr/bin/env python3
"""Compatibility shim — delegates to build_eval_datasets_cpp.py with sofa defaults."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_eval_datasets_cpp import main  # noqa: F401

REPO_ROOT = Path(__file__).parent.parent

# Inject sofa-specific defaults if the caller passed no arguments.
if len(sys.argv) == 1:
    sys.argv += [
        "--runs-dir", str(REPO_ROOT / "attacker" / "runs" / "qwen3.6-27b"),
        "--out-root", str(REPO_ROOT / "benchmark" / "sofa_qwen3_27b"),
        "--dataset", "sofa-pbrpc-npd",
    ]

main()
