#!/usr/bin/env python3
"""
Run VulTrial (gpt-4o) over the full 128-sample CVE benchmark.
Parallel + resume logic lives in adaptive_attacker/eval_vultrial.py.

Usage:
    cd /mnt/ssd/aryawu/redteaming_code_auditors
    python scripts/oneoff/run_vultrial_cvebench_full.py [--workers 8] [--dry-run]
"""
import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))
sys.path.insert(0, str(REPO_ROOT))

from eval_vultrial import run

BASELINE_DIR = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
ATTACK_DIR   = REPO_ROOT / "adaptive_attacker" / "results" / "vulnllmr_full"
OUT_ROOT     = REPO_ROOT / "adaptive_attacker" / "results" / "vultrial_full"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--slugs",   nargs="+")
    parser.add_argument("--out-root", type=Path, default=OUT_ROOT,
                        help="Output dir. Defaults to vultrial_full; use a fresh "
                             "dir (e.g. vultrial_transfer_verbatim) to avoid "
                             "clobbering from-scratch results.")
    args = parser.parse_args()

    slugs = args.slugs or sorted(
        d.name.replace("repository_", "")
        for d in BASELINE_DIR.iterdir()
        if d.is_dir() and d.name.startswith("repository_NPD-CVE-")
    )

    run(
        slugs        = slugs,
        baseline_dir = BASELINE_DIR,
        attack_dir   = ATTACK_DIR,
        out_root     = args.out_root,
        workers      = args.workers,
        dry_run      = args.dry_run,
    )


if __name__ == "__main__":
    main()
