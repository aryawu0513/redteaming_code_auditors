#!/usr/bin/env python3
"""
Push the CVE NPD benchmark to HuggingFace Hub as a dataset.

Reads all _CLEAN.json files from benchmark/<name>/baseline/ and pushes
them as a single JSONL dataset split.

Usage:
  huggingface-cli login   # once
  python3 cvebench/push_to_hub.py \\
      --bench-root benchmark/cvebench_full \\
      --repo-id  AryaWu/cvebench_full \\
      [--private]
"""

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench-root", required=True,
                    help="e.g. benchmark/cvebench_r1r2")
    ap.add_argument("--repo-id",    required=True,
                    help="HuggingFace repo id, e.g. myorg/cve-npd-bench")
    ap.add_argument("--private",    action="store_true")
    ap.add_argument("--split",      default="train")
    args = ap.parse_args()

    bench_root = REPO_ROOT / args.bench_root / "baseline"
    if not bench_root.exists():
        raise SystemExit(f"Not found: {bench_root}")

    records = []
    for json_file in sorted(bench_root.glob("repository_*/*_CLEAN.json")):
        data = json.loads(json_file.read_text())
        if isinstance(data, list):
            records.extend(data)
        else:
            records.append(data)

    print(f"Loaded {len(records)} records from {bench_root}")

    try:
        from datasets import Dataset
        from huggingface_hub import HfApi
    except ImportError:
        raise SystemExit("pip install datasets huggingface_hub")

    ds = Dataset.from_list(records)
    ds.push_to_hub(
        args.repo_id,
        split=args.split,
        private=args.private,
    )
    print(f"Pushed {len(records)} records → https://huggingface.co/datasets/{args.repo_id}")

    readme = Path(__file__).parent / "DATASET_README.md"
    if readme.exists():
        api = HfApi()
        api.upload_file(
            path_or_fileobj=str(readme),
            path_in_repo="README.md",
            repo_id=args.repo_id,
            repo_type="dataset",
        )
        print("Uploaded DATASET_README.md → README.md")


if __name__ == "__main__":
    main()
