#!/usr/bin/env python3
"""
screen_benchmark.py — Run D3 comment screening on benchmark attack files once.

Reads .c/.py attack files from RepoAudit/benchmark/{subtree}/ (all categories),
labels every comment via the D3 screening agent, and saves the results to
defenses/texts/D3_labeled/{subtree}/.  Both apply_repoaudit.py and
apply_vulnllm.py check this location first and skip the LLM call if it exists.

Usage:
    python defenses/screen_benchmark.py --subtree C/NPD
    python defenses/screen_benchmark.py --subtree C/UAF
    python defenses/screen_benchmark.py --subtree Python/NPD
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from defenses.screening_agent import label_files

BASE          = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RA_BENCH      = os.path.join(BASE, 'RepoAudit', 'benchmark')
TEXTS_LABELED = os.path.join(BASE, 'defenses', 'texts', 'D3_labeled')


def screen_subtree(subtree: str) -> None:
    src = os.path.join(RA_BENCH, subtree)
    dst = os.path.join(TEXTS_LABELED, subtree)

    if os.path.exists(dst):
        print(f"[screen] Reusing: {dst}")
        return

    if not os.path.exists(src):
        raise FileNotFoundError(f"[screen] Benchmark not found: {src}")

    ext = '.py' if subtree.startswith('Python') else '.c'
    shutil.copytree(src, dst)

    file_map = {}
    for root, _, files in os.walk(dst):
        for fname in files:
            if fname.endswith(ext):
                fpath = os.path.join(root, fname)
                file_map[fpath] = open(fpath).read()

    print(f"[screen] Labeling {len(file_map)} {ext} files (LLM call)...")
    results = label_files(file_map)
    bad = 0
    for fpath, (labeled, unchanged) in results.items():
        if not unchanged:
            print(f"[screen] WARNING: screener modified executable code in {fpath}")
            bad += 1
        with open(fpath, 'w') as f:
            f.write(labeled)
    if bad:
        print(f"[screen] {bad} file(s) had executable code changes — review before using.")
    print(f"[screen] Done: {dst}")


def main():
    parser = argparse.ArgumentParser(
        description='Screen benchmark .c/.py files once for D3 defense; saves to defenses/texts/D3_labeled/')
    parser.add_argument('--subtree', required=True,
                        help='Benchmark subtree, e.g. C/NPD, C/UAF, Python/NPD')
    args = parser.parse_args()
    screen_subtree(args.subtree)


if __name__ == '__main__':
    main()
