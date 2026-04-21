#!/usr/bin/env python3
"""Test the consolidated gen_attacks.py by writing output to automatic/output_test/
and diffing against the ground truth in RepoAudit/benchmark/ and VulnLLM-R/datasets/."""

import os
import subprocess
import sys

REPO = "/mnt/ssd/aryawu/redteaming_repoaudit"
OUT  = os.path.join(REPO, "automatic", "output_test")
sys.path.insert(0, REPO)

from automatic.gen_attacks import generate_all, CONFIG

SUBTREES = [
    # (language, bug_type, ra_gt,                      vl_gt,                       ra_out,              vl_out)
    ("c",      "npd",
     f"{REPO}/RepoAudit/benchmark/C/NPD",
     f"{REPO}/VulnLLM-R/datasets/C/NPD",
     f"{OUT}/repoaudit/C/NPD",
     f"{OUT}/vulnllm/C/NPD"),
    ("c",      "uaf",
     f"{REPO}/RepoAudit/benchmark/C/UAF",
     f"{REPO}/VulnLLM-R/datasets/C/UAF",
     f"{OUT}/repoaudit/C/UAF",
     f"{OUT}/vulnllm/C/UAF"),
    ("python", "npd",
     f"{REPO}/RepoAudit/benchmark/Python/NPD",
     f"{REPO}/VulnLLM-R/datasets/Python/NPD",
     f"{OUT}/repoaudit/Python/NPD",
     f"{OUT}/vulnllm/Python/NPD"),
    ("c",      "npd_annotated",
     f"{REPO}/RepoAudit/benchmark/C/NPD",
     f"{REPO}/VulnLLM-R/datasets/C/NPD",
     f"{OUT}/repoaudit/C/NPD",
     f"{OUT}/vulnllm/C/NPD"),
]

def diff_subdirs(gt_base, out_base, subdirs):
    """Diff specific subdirectories between gt_base and out_base."""
    diffs = []
    for subdir in subdirs:
        gt  = os.path.join(gt_base,  subdir)
        out = os.path.join(out_base, subdir)
        if not os.path.isdir(gt):
            continue
        result = subprocess.run(
            ["diff", "-rq", "--exclude=*.log", "--exclude=dpi_think", gt, out],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            diffs.append(result.stdout)
    return "\n".join(diffs)

all_clean = True

for language, bug_type, ra_gt, vl_gt, ra_out, vl_out in SUBTREES:
    label      = f"{language.upper()}/{bug_type.upper()}"
    cfg        = CONFIG[(language, bug_type)]
    dir_prefix = cfg.get("dir_prefix", "")
    subdirs    = [f"{dir_prefix}clean", f"{dir_prefix}dpi", f"{dir_prefix}context_aware"]

    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")

    generate_all(language, bug_type, ra_base=ra_out, vl_base=vl_out)

    for gt, out, sys_label in [(ra_gt, ra_out, "RepoAudit"), (vl_gt, vl_out, "VulnLLM-R")]:
        diff = diff_subdirs(gt, out, subdirs)
        if diff:
            print(f"\n  [{sys_label}] DIFF:")
            print(diff)
            all_clean = False
        else:
            print(f"  [{sys_label}] OK — identical to ground truth")

print()
if all_clean:
    print("All outputs match ground truth.")
else:
    print("Differences found — see above.")
    sys.exit(1)
