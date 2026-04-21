#!/usr/bin/env python3
"""
build_attacks.py — Construct attacked repos from a texts JSON file.

Reads demo/texts/demo.json (written by attack_agent.py) and writes one
attacked repo per attack type under demo/target_repo_attacks/.

Usage:
    python demo/build_attacks.py \\
        [--texts  demo/texts/demo.json] \\
        [--repo   demo/target_repo] \\
        [--output demo/target_repo_attacks]
"""

import argparse
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from automatic.gen_attacks import inject

DEMO_DIR = os.path.dirname(os.path.abspath(__file__))


def write_attacked_repo(repo_path: str, output_path: str,
                        target_filename: str, attacked_content: str):
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    shutil.copytree(repo_path, output_path)
    dest = os.path.join(output_path, target_filename)
    with open(dest, "w") as f:
        f.write(attacked_content)


def main():
    parser = argparse.ArgumentParser(description="Build attacked repos from texts JSON.")
    parser.add_argument("--texts",  default=os.path.join(DEMO_DIR, "texts", "demo.json"),
                        help="Path to texts JSON (default: demo/texts/demo.json)")
    parser.add_argument("--repo",   default=os.path.join(DEMO_DIR, "target_repo"),
                        help="Path to the clean target repo (default: demo/target_repo)")
    parser.add_argument("--output", default=os.path.join(DEMO_DIR, "target_repo_attacks"),
                        help="Output directory for attacked repos (default: demo/target_repo_attacks)")
    parser.add_argument("--attack-type", nargs="+", dest="attack_types",
                        help="Subset of attack types to build (default: all keys in texts JSON)")
    args = parser.parse_args()

    if not os.path.exists(args.texts):
        print(f"ERROR: texts file not found: {args.texts}", file=sys.stderr)
        print("Run attack_agent.py first.", file=sys.stderr)
        sys.exit(1)

    with open(args.texts) as f:
        data = json.load(f)

    meta = data.get("meta")
    if not meta:
        print("ERROR: texts JSON missing 'meta' key", file=sys.stderr)
        sys.exit(1)

    # Read the target file from the clean repo
    target_filepath = os.path.join(args.repo, meta["target_filename"])
    if not os.path.exists(target_filepath):
        print(f"ERROR: target file not found: {target_filepath}", file=sys.stderr)
        sys.exit(1)
    with open(target_filepath) as f:
        clean_content = f.read()

    # Determine which attack types to build
    available = [k for k in data if k != "meta"]
    attack_types = args.attack_types if args.attack_types else available
    for t in attack_types:
        if t not in data:
            print(f"ERROR: attack type '{t}' not in texts JSON (available: {available})", file=sys.stderr)
            sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    built = []
    for attack_type in attack_types:
        payload = data[attack_type]
        attacked_content = inject(
            clean_content,
            between_call_and_deref=payload,
            call_line=meta["call_line"],
            deref_line=meta["deref_line"],
        )
        out_dir = os.path.join(args.output, f"attacked_repo_{attack_type}")
        write_attacked_repo(args.repo, out_dir, meta["target_filename"], attacked_content)
        built.append(out_dir)
        print(f"  [{attack_type}] → {out_dir}/")

    print(f"\n[build_attacks] Done. {len(built)} attacked repo(s) written to {args.output}/")


if __name__ == "__main__":
    main()
