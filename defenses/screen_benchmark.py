#!/usr/bin/env python3
"""
screen_benchmark.py — Run D3 or D4 comment screening on benchmark attack files once.

Reads .c/.py attack files from RepoAudit/benchmark/{subtree}/, screens every comment
via the LLM screening agent, and saves results to defenses/texts/{D3_labeled,D4_labeled}/{subtree}/.

Both apply_repoaudit.py and apply_vulnllm.py check these locations first and skip the
LLM call if the cache already exists.

Usage:
    python defenses/screen_benchmark.py --defense D3 --subtree C/NPD
    python defenses/screen_benchmark.py --defense D4 --subtree C/NPD
    python defenses/screen_benchmark.py --defense D3 --subtree Python/NPD
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RA_BENCH = os.path.join(BASE, 'RepoAudit', 'benchmark')
TEXTS    = os.path.join(BASE, 'defenses', 'texts')


def screen_subtree(defense: str, subtree: str) -> None:
    label_tag = 'D4_labeled' if defense == 'D4' else 'D3_labeled'
    src = os.path.join(RA_BENCH, subtree)
    dst = os.path.join(TEXTS, label_tag, subtree)

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

    print(f"[screen] {defense}: labeling {len(file_map)} {ext} files (LLM call)...")
    if defense == 'D4':
        from defenses.screening_agent import label_files_d4
        results = label_files_d4(file_map)
    else:
        from defenses.screening_agent import label_files
        results = label_files(file_map)

    bad = 0
    for fpath, (labeled, unchanged) in results.items():
        if not unchanged and defense == 'D3':
            print(f"[screen] WARNING: screener modified executable code in {fpath}")
            bad += 1
        with open(fpath, 'w') as f:
            f.write(labeled)
    if bad:
        print(f"[screen] {bad} file(s) had executable code changes — review before using.")
    print(f"[screen] Done: {dst}")


def main():
    parser = argparse.ArgumentParser(
        description='Screen benchmark .c/.py files once; saves to defenses/texts/{D3,D4}_labeled/')
    parser.add_argument('--defense', required=True, choices=['D3', 'D4'])
    parser.add_argument('--subtree', required=True,
                        help='Benchmark subtree, e.g. C/NPD, C/UAF, Python/NPD')
    args = parser.parse_args()
    screen_subtree(args.defense, args.subtree)


if __name__ == '__main__':
    main()
