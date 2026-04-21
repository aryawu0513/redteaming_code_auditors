#!/usr/bin/env python3
"""
Rebuild D3L/D3A/D3B variant dirs from D3_labeled (pure regex, no LLM).

Run this after re-screening D3_labeled to regenerate all variant dirs for
both RepoAudit (benchmark-defense/) and VulnLLM-R (datasets-defense/).

Usage:
    python defenses/rebuild_variants.py                         # all subtrees
    python defenses/rebuild_variants.py --subtree Python/NPD    # one subtree
    python defenses/rebuild_variants.py --system RepoAudit      # one system
"""
import argparse, glob, json, os, shutil, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from defenses.screening_agent import apply_variant

ALL_SUBTREES = ['C/NPD', 'C/UAF', 'Python/NPD']
ALL_VARIANTS = [('D3L', 'labeled'), ('D3A', 'A'), ('D3B', 'B')]


def rebuild_repoaudit(subtree: str, variants=ALL_VARIANTS):
    bench_defense = os.path.join(BASE, 'RepoAudit', 'benchmark-defense')
    labeled = os.path.join(bench_defense, 'D3_labeled', subtree)
    if not os.path.exists(labeled):
        print(f"[skip] RepoAudit D3_labeled/{subtree} not found")
        return
    ext = '.py' if subtree.startswith('Python') else '.c'
    for variant_name, variant_key in variants:
        dst = os.path.join(bench_defense, variant_name, subtree)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        shutil.copytree(labeled, dst)
        for fpath in glob.glob(os.path.join(dst, '**', f'*{ext}'), recursive=True):
            with open(fpath) as f:
                txt = f.read()
            with open(fpath, 'w') as f:
                f.write(apply_variant(txt, variant_key))
        print(f"RepoAudit {variant_name}/{subtree} done")


def rebuild_vulnllm(subtree: str, variants=ALL_VARIANTS):
    ds_defense = os.path.join(BASE, 'VulnLLM-R', 'datasets-defense')
    labeled = os.path.join(ds_defense, 'D3_labeled', subtree)
    if not os.path.exists(labeled):
        print(f"[skip] VulnLLM-R D3_labeled/{subtree} not found")
        return
    for variant_name, variant_key in variants:
        dst = os.path.join(ds_defense, variant_name, subtree)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        shutil.copytree(labeled, dst)
        for fpath in glob.glob(os.path.join(dst, '**', '*.json'), recursive=True):
            with open(fpath) as f:
                data = json.load(f)
            for item in data:
                if isinstance(item, dict) and 'code' in item:
                    item['code'] = apply_variant(item['code'], variant_key)
            with open(fpath, 'w') as f:
                json.dump(data, f, indent=2)
        print(f"VulnLLM-R {variant_name}/{subtree} done")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--subtree', help='e.g. C/NPD, C/UAF, Python/NPD (default: all)')
    parser.add_argument('--system', choices=['RepoAudit', 'VulnLLM-R'],
                        help='Limit to one system (default: both)')
    args = parser.parse_args()

    subtrees = [args.subtree] if args.subtree else ALL_SUBTREES

    for subtree in subtrees:
        if args.system != 'VulnLLM-R':
            rebuild_repoaudit(subtree)
        if args.system != 'RepoAudit':
            rebuild_vulnllm(subtree)


if __name__ == '__main__':
    main()
