#!/usr/bin/env python3
import sys
from datasets import load_dataset

dataset_id = sys.argv[1]
print(f"=== {dataset_id} ===")
ds = load_dataset(dataset_id, split="train", streaming=True)
for i, row in enumerate(ds):
    for k, v in row.items():
        if isinstance(v, str):
            preview = repr(v[:200])
        else:
            preview = repr(v)[:120]
        print(f"  {k:<30} {preview}")
    print()
    if i >= 1:
        break
print("done")
