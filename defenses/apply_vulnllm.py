#!/usr/bin/env python3
"""
Apply a defense to VulnLLM-R:
  D1/D2  — set VL_TASK_ADDITION env var (injected as preamble in user prompt via sys_prompts.py)
  D3A/D3B/D4/D4_prepend — sanitize dataset JSON code fields via screening agent,
                           redirect VL_DATASET_PREFIX

Usage:
    python defenses/apply_vulnllm.py --defense D1 --run-script run_npd_c_attacks.sh
    python defenses/apply_vulnllm.py --defense D3B --run-script run_npd_c_attacks.sh
    python defenses/apply_vulnllm.py --defense D3A --subtree C/UAF --preprocess-only
    python defenses/apply_vulnllm.py --defense D3L --subtree Python/NPD --run-script run_npd_python_attacks.sh
    python defenses/apply_vulnllm.py --defense D4 --subtree C/NPD --preprocess-only
"""
import argparse, os, subprocess, sys

BASE        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VL_BASE     = os.path.join(BASE, 'VulnLLM-R')
VL_DATASETS = os.path.join(VL_BASE, 'datasets')
TEXTS_D3    = os.path.join(BASE, 'defenses', 'texts', 'D3_labeled')
sys.path.insert(0, BASE)
from defenses.registry import DEFENSES



def rewrite_output_dir(output_dir: str, defense_name: str) -> str:
    """Redirect results/... to results-defense/{defense}/{...}"""
    if output_dir.startswith('results/'):
        return output_dir.replace('results/', f'results-defense/{defense_name}/', 1)
    return os.path.join(f'results-defense/{defense_name}', output_dir)


def migrate_d4_labeled(subtree: str = 'C/NPD') -> None:
    """Extract audit blocks from D4_prepend_labeled and write separator format to D4_labeled.
    Also produces the final D4 (append) and D4_prepend (prepend) datasets as a side effect.
    Overwrites existing files; does not delete directories.
    """
    import json as _json, glob as _glob, shutil as _shutil
    from defenses.screening_agent import AUDIT_SEPARATOR, extract_from_prepend_labeled, apply_variant

    src_dir = os.path.join(VL_BASE, 'datasets-defense', 'D4_prepend_labeled', subtree)
    if not os.path.exists(src_dir):
        raise FileNotFoundError(f"[migrate] Source not found: {src_dir}")

    lang = 'python' if subtree.startswith('Python') else 'c'
    labeled_dir = os.path.join(VL_BASE, 'datasets-defense', 'D4_labeled', subtree)
    append_dir  = os.path.join(VL_BASE, 'datasets-defense', 'D4_append',  subtree)
    prepend_dir = os.path.join(VL_BASE, 'datasets-defense', 'D4_prepend', subtree)

    json_files = _glob.glob(os.path.join(src_dir, '**', '*.json'), recursive=True)
    print(f"[migrate] {len(json_files)} JSON files from {src_dir}")

    for src_fpath in json_files:
        rel = os.path.relpath(src_fpath, src_dir)
        with open(src_fpath) as f:
            data = _json.load(f)

        labeled_data = [dict(item) for item in data]
        append_data  = [dict(item) for item in data]
        prepend_data = [dict(item) for item in data]

        for i, item in enumerate(data):
            if not isinstance(item, dict) or 'code' not in item:
                continue
            sep_code = extract_from_prepend_labeled(item['code'])
            labeled_data[i]['code'] = sep_code
            append_data[i]['code']  = apply_variant(sep_code, 'D4_append',  lang=lang)
            prepend_data[i]['code'] = apply_variant(sep_code, 'D4_prepend', lang=lang)

        for dst_dir, out_data in [(labeled_dir, labeled_data),
                                   (append_dir,  append_data),
                                   (prepend_dir, prepend_data)]:
            dst_fpath = os.path.join(dst_dir, rel)
            os.makedirs(os.path.dirname(dst_fpath), exist_ok=True)
            with open(dst_fpath, 'w') as f:
                _json.dump(out_data, f, indent=2)

    print(f"[migrate] Done: D4_labeled, D4, D4_prepend for {subtree}")


def build_vl_datasets(defense_name: str, variant: str, subtree: str = 'C/NPD',
                      preprocess_only: bool = False) -> str:
    """
    Two-stage dataset build for VulnLLM-R.
    Stage 1: LLM label → datasets-defense/D3_labeled/ or D4_labeled/ (shared, run once)
    Stage 2: variant regex/placement → datasets-defense/{defense_name}/
    Returns path to the final variant dataset dir.
    """
    import json as _json, shutil as _shutil, glob as _glob
    from defenses.screening_agent import label_files, apply_variant, AUDIT_SEPARATOR

    is_d4     = defense_name in ('D4_append', 'D4_prepend')
    label_tag = 'D4_labeled' if is_d4 else 'D3_labeled'
    lang      = 'python' if subtree.startswith('Python') else 'c'

    labeled_datasets = os.path.join(VL_BASE, 'datasets-defense', label_tag)
    labeled_subtree  = os.path.join(labeled_datasets, subtree)
    dst_datasets     = os.path.join(VL_BASE, 'datasets-defense', defense_name)
    dst_subtree      = os.path.join(dst_datasets, subtree)

    # Stage 1: label once per subtree (D3 only; D4 has its own flow unchanged below)
    if os.path.exists(labeled_subtree):
        print(f"[defense] Reusing labeled datasets: {labeled_subtree}")
    elif is_d4:
        # D4: prefer extraction from D4_prepend_labeled (no LLM cost)
        prepend_src = os.path.join(VL_BASE, 'datasets-defense', 'D4_prepend_labeled', subtree)
        if os.path.exists(prepend_src):
            print(f"[defense] Extracting D4_labeled from D4_prepend_labeled (no LLM)...")
            migrate_d4_labeled(subtree)
            print(f"[defense] Extraction done: {labeled_subtree}")
        else:
            _shutil.copytree(os.path.join(VL_DATASETS, subtree), labeled_subtree)
            json_files = _glob.glob(os.path.join(labeled_subtree, '**', '*.json'), recursive=True)
            file_map, json_data = {}, {}
            for fpath in json_files:
                with open(fpath) as f:
                    data = _json.load(f)
                json_data[fpath] = data
                for i, item in enumerate(data):
                    if isinstance(item, dict) and 'code' in item:
                        file_map[f"{fpath}::{i}"] = item['code']
            print(f"[defense] Labeling {len(file_map)} JSON code entries (LLM call)...")
            from defenses.screening_agent import label_files_d4
            results = label_files_d4(file_map)
            for key, (labeled, _) in results.items():
                fpath, idx = key.rsplit('::', 1)
                json_data[fpath][int(idx)]['code'] = labeled
            for fpath, data in json_data.items():
                with open(fpath, 'w') as f:
                    _json.dump(data, f, indent=2)
            print(f"[defense] Labeling done: {labeled_datasets}")
    else:
        # D3: check if RA already screened the same source files
        texts_labeled_subtree = os.path.join(TEXTS_D3, subtree)
        if os.path.exists(texts_labeled_subtree):
            # Convert labeled .c/.py files → labeled JSON (1-to-1 by stem name)
            print(f"[defense] Converting RA-labeled files from {texts_labeled_subtree}...")
            ext = '.py' if subtree.startswith('Python') else '.c'
            json_files = _glob.glob(os.path.join(VL_DATASETS, subtree, '**', '*.json'), recursive=True)
            for jpath in json_files:
                rel  = os.path.relpath(jpath, os.path.join(VL_DATASETS, subtree))
                # Corresponding labeled .c: remove /c/ subdir from rel path, change ext
                # e.g. context_aware/creatend/c/creatend_COT.json → context_aware/creatend/creatend_COT.c
                rel_parts = rel.replace(os.sep, '/').split('/')
                rel_no_lang = '/'.join(p for p in rel_parts if p not in ('c', 'python'))
                c_rel = os.path.splitext(rel_no_lang)[0] + ext
                c_path = os.path.join(texts_labeled_subtree, c_rel)
                if not os.path.exists(c_path):
                    continue
                labeled_code = open(c_path).read()
                with open(jpath) as f:
                    data = _json.load(f)
                for item in data:
                    if isinstance(item, dict) and 'code' in item:
                        item['code'] = labeled_code
                dst = os.path.join(labeled_subtree, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, 'w') as f:
                    _json.dump(data, f, indent=2)
            print(f"[defense] Conversion done: {labeled_subtree}")
        else:
            # Screen from scratch; also save labeled .c copies to defenses/texts/D3_labeled/
            _shutil.copytree(os.path.join(VL_DATASETS, subtree), labeled_subtree)
            json_files = _glob.glob(os.path.join(labeled_subtree, '**', '*.json'), recursive=True)
            file_map, json_data = {}, {}
            for fpath in json_files:
                with open(fpath) as f:
                    data = _json.load(f)
                json_data[fpath] = data
                for i, item in enumerate(data):
                    if isinstance(item, dict) and 'code' in item:
                        file_map[f"{fpath}::{i}"] = item['code']
            print(f"[defense] Labeling {len(file_map)} JSON code entries (LLM call)...")
            results = label_files(file_map)
            bad = 0
            for key, (labeled, unchanged) in results.items():
                fpath, idx = key.rsplit('::', 1)
                if not unchanged:
                    print(f"[defense] WARNING: screener modified executable code in {fpath}::{idx}")
                    bad += 1
                json_data[fpath][int(idx)]['code'] = labeled
            for fpath, data in json_data.items():
                with open(fpath, 'w') as f:
                    _json.dump(data, f, indent=2)
            if bad:
                print(f"[defense] {bad} entry/entries had executable code changes.")
            print(f"[defense] Labeling done: {labeled_datasets}")
            # Save labeled .c copies so RA can reuse without re-screening
            ext = '.py' if subtree.startswith('Python') else '.c'
            for jpath, data in json_data.items():
                rel  = os.path.relpath(jpath, labeled_subtree)
                rel_parts = rel.replace(os.sep, '/').split('/')
                rel_no_lang = '/'.join(p for p in rel_parts if p not in ('c', 'python'))
                for item in data:
                    if isinstance(item, dict) and 'code' in item:
                        c_rel = os.path.splitext(rel_no_lang)[0] + ext
                        c_path = os.path.join(texts_labeled_subtree, c_rel)
                        os.makedirs(os.path.dirname(c_path), exist_ok=True)
                        with open(c_path, 'w') as f:
                            f.write(item['code'])
                        break  # one .c per JSON file

    if preprocess_only:
        print(f"[defense] Preprocess complete. Inspect datasets-defense/{label_tag}/{subtree}/ then run without --preprocess-only.")
        sys.exit(0)

    # Stage 2: apply variant placement per subtree
    # D4 uses defense_name ('D4_append'/'D4_prepend') to determine placement;
    # D3 uses screening_variant ('labeled'/'A'/'B'), not the defense name.
    apply_key = defense_name if is_d4 else variant
    if os.path.exists(dst_subtree):
        print(f"[defense] Reusing sanitized datasets: {dst_subtree}")
    else:
        _shutil.copytree(labeled_subtree, dst_subtree)
        json_files = _glob.glob(os.path.join(dst_subtree, '**', '*.json'), recursive=True)
        for fpath in json_files:
            with open(fpath) as f:
                data = _json.load(f)
            for item in data:
                if isinstance(item, dict) and 'code' in item:
                    item['code'] = apply_variant(item['code'], apply_key, lang=lang)
            with open(fpath, 'w') as f:
                _json.dump(data, f, indent=2)
        print(f"[defense] Variant {apply_key} applied: {dst_subtree}")

    return dst_datasets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--defense', required=True, choices=list(DEFENSES.keys()))
    parser.add_argument('--run-script', help='Run a shell script from VulnLLM-R dir with defense env')
    parser.add_argument('--preprocess-only', action='store_true',
                        help='For D3A/D3B: run LLM labeling only, do not launch benchmark')
    parser.add_argument('--subtree', default='C/NPD',
                        help='Dataset subtree to process, e.g. C/NPD (default), C/UAF, Python/NPD')
    parser.add_argument('rest', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    defense = DEFENSES[args.defense]
    print(f"[defense] Applying {args.defense}: {defense['description']}")

    if args.run_script:
        env = os.environ.copy()
        env['VL_RESULT_PREFIX'] = f'results-defense/{args.defense}'

        if 'screening_variant' in defense:
            dst_datasets = build_vl_datasets(args.defense, defense['screening_variant'],
                                             subtree=args.subtree,
                                             preprocess_only=args.preprocess_only)
            env['VL_DATASET_PREFIX'] = dst_datasets
            print(f"[defense] Dataset dir: {dst_datasets}")

        if 'task_addition' in defense:
            env['VL_TASK_ADDITION'] = defense['task_addition']

        script = os.path.join(VL_BASE, args.run_script)
        result = subprocess.run(['bash', script], env=env, cwd=VL_BASE)
        sys.exit(result.returncode)

    # Direct invocation (no --run-script)
    if 'screening_variant' in defense:
        dst = build_vl_datasets(args.defense, defense['screening_variant'],
                                subtree=args.subtree,
                                preprocess_only=args.preprocess_only)
        os.environ['VL_DATASET_PREFIX'] = dst

    if 'task_addition' in defense:
        os.environ['VL_TASK_ADDITION'] = defense['task_addition']

    # Rewrite --output_dir in the remaining args
    rest = args.rest
    if '--' in rest:
        rest = rest[rest.index('--') + 1:]

    new_args = []
    i = 0
    while i < len(rest):
        if rest[i] == '--output_dir' and i + 1 < len(rest):
            new_args.append('--output_dir')
            new_args.append(rewrite_output_dir(rest[i+1], args.defense))
            i += 2
        elif rest[i] == '--dataset_path' and i + 1 < len(rest) and 'VL_DATASET_PREFIX' in os.environ:
            # Remap dataset_path to sanitized dir
            orig = rest[i+1]
            rel = os.path.relpath(orig, VL_DATASETS)
            new_args.append('--dataset_path')
            new_args.append(os.path.join(os.environ['VL_DATASET_PREFIX'], rel))
            i += 2
        else:
            new_args.append(rest[i])
            i += 1

    if not new_args:
        print("[defense] No command given. Dataset ready at:", os.environ.get('VL_DATASET_PREFIX', '(env set)'))
        sys.exit(0)

    sys.argv = ['test.py'] + new_args
    os.chdir(VL_BASE)
    exec(open(os.path.join(VL_BASE, 'vulscan/test/test.py')).read(),
         {'__name__': '__main__', '__file__': os.path.join(VL_BASE, 'vulscan/test/test.py')})


if __name__ == '__main__':
    main()
