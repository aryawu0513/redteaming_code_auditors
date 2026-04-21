#!/usr/bin/env python3
"""
Apply a defense to RepoAudit by:
1. (D1/D2) Copying the prompt JSON files to a temp directory with defense additions injected
2. (D3A/D3B) Copying the benchmark source files to a temp directory with comments sanitized
3. Setting RA_PROMPT_ROOT, RA_RESULT_ROOT, RA_BENCH_ROOT env vars
4. Exec-ing the given run_repoaudit.sh command

Usage:
    python defenses/apply_repoaudit.py --defense D1 -- bash run_npd_c_attacks.sh
    python defenses/apply_repoaudit.py --defense D3B -- bash run_npd_c_attacks.sh
    python defenses/apply_repoaudit.py --defense D3A --subtree C/UAF --preprocess-only
    python defenses/apply_repoaudit.py --defense D3L --subtree C/UAF -- bash run_uaf_c_attacks.sh
"""
import argparse, json, os, shutil, subprocess, sys, tempfile  # tempfile used for D1/D2 prompt dir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from defenses.registry import DEFENSES

BASE    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
RA_SRC  = os.path.join(BASE, 'RepoAudit', 'src')
RA_BASE = os.path.dirname(RA_SRC)   # RepoAudit/
RA_BENCH = os.path.join(RA_BASE, 'benchmark')



def build_prompt_dir(defense_name: str, tmpdir: str) -> str:
    """Copy prompt/ into tmpdir, injecting defense task_addition into task field."""
    defense = DEFENSES[defense_name]
    src_prompt = os.path.join(RA_SRC, 'prompt')
    dst_prompt = os.path.join(tmpdir, 'prompt')
    shutil.copytree(src_prompt, dst_prompt)

    task_addition = defense['task_addition']
    is_d4 = defense_name in ('D4_append', 'D4_prepend')

    for lang in os.listdir(dst_prompt):
        dfbscan_dir = os.path.join(dst_prompt, lang, 'dfbscan')
        if not os.path.isdir(dfbscan_dir):
            continue
        for fname in ['path_validator.json', 'intra_dataflow_analyzer.json']:
            fpath = os.path.join(dfbscan_dir, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath) as f:
                data = json.load(f)
            data['task'] = data['task'] + ' ' + task_addition
            if is_d4 and 'meta_prompts' in data:
                data['meta_prompts'][0] = '<AUDIT_BLOCK>\n\n' + data['meta_prompts'][0]
            with open(fpath, 'w') as f:
                json.dump(data, f, indent=2)

    return tmpdir


def build_labeled_bench_dir(subtree: str = 'C/NPD', defense_name: str = 'D3') -> str:
    """Run LLM labeling on all .c/.py files once; save to defenses/texts/D3_labeled/{subtree}/."""
    label_tag = 'D4_labeled' if defense_name in ('D4_append', 'D4_prepend') else 'D3_labeled'
    if label_tag == 'D3_labeled':
        labeled_dir = os.path.join(BASE, 'defenses', 'texts', 'D3_labeled')
    else:
        labeled_dir = os.path.join(RA_BASE, 'benchmark-defense', label_tag)
    labeled_subtree = os.path.join(labeled_dir, subtree)
    if os.path.exists(labeled_subtree):
        print(f"[defense] Reusing labeled benchmark: {labeled_subtree}")
        return labeled_dir

    shutil.copytree(os.path.join(RA_BENCH, subtree), labeled_subtree)
    ext = '.py' if subtree.startswith('Python') else '.c'
    file_map = {}
    for root, _, files in os.walk(labeled_subtree):
        for fname in files:
            if fname.endswith(ext):
                fpath = os.path.join(root, fname)
                file_map[fpath] = open(fpath).read()

    print(f"[defense] Labeling {len(file_map)} {ext} files (LLM call)...")
    if defense_name in ('D4_append', 'D4_prepend'):
        from defenses.screening_agent import label_files_d4
        results = label_files_d4(file_map)
    else:
        from defenses.screening_agent import label_files
        results = label_files(file_map)
    bad = 0
    for fpath, (labeled, unchanged) in results.items():
        if not unchanged and defense_name not in ('D4_append', 'D4_prepend'):
            print(f"[defense] WARNING: screener modified executable code in {fpath}")
            bad += 1
        with open(fpath, 'w') as f:
            f.write(labeled)
    if bad:
        print(f"[defense] {bad} file(s) had executable code changes.")
    print(f"[defense] Labeling done: {labeled_dir}")
    return labeled_dir


def build_bench_dir(defense_name: str, subtree: str = 'C/NPD') -> str:
    """Apply variant post-processing to labeled files; save to benchmark-defense/{name}/{subtree}/."""
    from defenses.screening_agent import apply_variant
    defense      = DEFENSES[defense_name]
    variant      = defense['screening_variant']
    dst_bench    = os.path.join(RA_BASE, 'benchmark-defense', defense_name)
    dst_subtree  = os.path.join(dst_bench, subtree)

    if os.path.exists(dst_subtree):
        print(f"[defense] Reusing sanitized benchmark: {dst_subtree}")
        return dst_bench

    d4 = defense_name in ('D4_append', 'D4_prepend')
    # For D4 defenses, apply_variant needs the defense name (not screening_variant='D4')
    # to determine placement; for D3 defenses, variant ('A'/'B'/'labeled') is correct.
    apply_key = defense_name if d4 else variant
    labeled_dir = build_labeled_bench_dir(subtree, defense_name=defense_name if d4 else 'D3')
    shutil.copytree(os.path.join(labeled_dir, subtree), dst_subtree)

    ext = '.py' if subtree.startswith('Python') else '.c'
    lang = 'python' if subtree.startswith('Python') else 'c'
    for root, _, files in os.walk(dst_subtree):
        for fname in files:
            if fname.endswith(ext):
                fpath = os.path.join(root, fname)
                labeled = open(fpath).read()
                with open(fpath, 'w') as f:
                    f.write(apply_variant(labeled, apply_key, lang=lang))

    print(f"[defense] Variant {variant} applied: {dst_subtree}")
    return dst_bench


def main():
    parser = argparse.ArgumentParser()
    # D4_append is excluded: for RepoAudit, D4_append and D4_prepend produce identical
    # prompts (audit block injected via <AUDIT_BLOCK> placeholder, not file placement).
    # Use D4_prepend only.
    RA_DEFENSES = [k for k in DEFENSES.keys() if k != 'D4_append']
    parser.add_argument('--defense', required=True, choices=RA_DEFENSES)
    parser.add_argument('--preprocess-only', action='store_true',
                        help='For D3A/D3B: run LLM labeling only, do not launch benchmark')
    parser.add_argument('--subtree', default='C/NPD',
                        help='Benchmark subtree to process, e.g. C/NPD (default), C/UAF, Python/NPD')
    parser.add_argument('cmd', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.cmd and args.cmd[0] == '--':
        args.cmd = args.cmd[1:]

    defense = DEFENSES[args.defense]
    print(f"[defense] Applying {args.defense}: {defense['description']}")

    result_root = os.path.join(RA_BASE, 'result-defense', args.defense)
    os.makedirs(result_root, exist_ok=True)

    env = os.environ.copy()
    env['RA_RESULT_ROOT'] = result_root

    if 'screening_variant' in defense:
        # D3A / D3B: sanitize benchmark files to fixed dir
        if args.preprocess_only:
            label_tag = 'D4_labeled' if args.defense in ('D4_append', 'D4_prepend') else 'D3_labeled'
            build_labeled_bench_dir(args.subtree, defense_name=args.defense)
            labeled_loc = f"defenses/texts/D3_labeled/{args.subtree}" if label_tag == 'D3_labeled' else f"RepoAudit/benchmark-defense/{label_tag}/{args.subtree}"
            print(f"[defense] Preprocess complete. Inspect {labeled_loc}/ then run without --preprocess-only.")
            sys.exit(0)
        bench_dir = build_bench_dir(args.defense, args.subtree)
        env['RA_BENCH_ROOT'] = bench_dir
        print(f"[defense] Bench dir: {bench_dir}")

    if 'task_addition' in defense:
        # inject into prompt JSON files
        with tempfile.TemporaryDirectory(prefix=f'ra_defense_{args.defense}_') as tmpdir:
            build_prompt_dir(args.defense, tmpdir)
            env['RA_PROMPT_ROOT'] = tmpdir
            print(f"[defense] Prompt dir: {tmpdir}/prompt")
            print(f"[defense] Result root: {result_root}")
            if args.cmd:
                result = subprocess.run(args.cmd, env=env, cwd=RA_SRC)
                sys.exit(result.returncode)
    else:
        print(f"[defense] Result root: {result_root}")
        if args.cmd:
            result = subprocess.run(args.cmd, env=env, cwd=RA_SRC)
            sys.exit(result.returncode)

    print("[defense] No command given. Env vars set:")
    for k in ('RA_PROMPT_ROOT', 'RA_BENCH_ROOT', 'RA_RESULT_ROOT'):
        if k in env:
            print(f"  {k}={env[k]}")


if __name__ == '__main__':
    main()
