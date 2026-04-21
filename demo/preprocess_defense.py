#!/usr/bin/env python3
"""
Pre-process attacked demo repos for D3L / D4_prepend defense evaluation.

For D3L: labels every comment (VERIFIABLE/INTENDED/UNVERIFIABLE/ADVERSARIAL),
         keeping all labels in-place so the auditor can reason about them.
For D4_prepend: builds a per-comment audit block with reasoning, prepended to the code.

Output: demo/target_repo_attacks_defense/{defense}/{repo}/attacked_repo_XX/

Usage (from repo root, with RepoAudit venv active):
    python demo/preprocess_defense.py --defense D3L --repo target_repo
    python demo/preprocess_defense.py --defense D4_prepend --repo target_repo
    python demo/preprocess_defense.py --defense D3L --defense D4_prepend --repo target_repo target_repo_v2

Notes:
  - Idempotent: skips repo dirs that already exist.
  - LLM call required (uses SCREENING_MODEL env var, defaults to claude-haiku-4-5-20251001).
  - set ANTHROPIC_API_KEY before running.
"""
import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.absolute()
DEMO_DIR  = Path(__file__).parent.absolute()

sys.path.insert(0, str(REPO_ROOT))


def process_repo(defense: str, repo: str) -> None:
    from defenses.screening_agent import label_files, label_files_d4, apply_variant

    attacks_src = DEMO_DIR / f"{repo}_attacks"
    if not attacks_src.exists():
        print(f"[preprocess] ERROR: source dir not found: {attacks_src}")
        return

    attacks_dst_root = DEMO_DIR / "target_repo_attacks_defense" / defense / repo
    attacks_dst_root.mkdir(parents=True, exist_ok=True)

    subdirs = sorted(
        p for p in attacks_src.iterdir()
        if p.is_dir() and p.name.startswith("attacked_repo_")
    )
    if not subdirs:
        print(f"[preprocess] No attacked_repo_* dirs found under {attacks_src}")
        return

    for repo_dir in subdirs:
        dst_dir = attacks_dst_root / repo_dir.name
        if dst_dir.exists():
            print(f"[preprocess] Skipping (exists): {dst_dir.relative_to(DEMO_DIR)}")
            continue

        c_files = {str(p): p.read_text() for p in sorted(repo_dir.glob("*.c"))}
        if not c_files:
            print(f"[preprocess] No .c files in {repo_dir.name} — copying as-is")
            shutil.copytree(repo_dir, dst_dir)
            continue

        print(f"[preprocess] {defense}/{repo}/{repo_dir.name} "
              f"— calling screening agent on {len(c_files)} file(s)…")

        if defense == "D4_prepend":
            results = label_files_d4(c_files)
            apply_key = "D4_prepend"
        else:  # D3L
            results = label_files(c_files)
            apply_key = "labeled"

        # Copy whole dir first (preserves .h files etc.) then overwrite .c files.
        shutil.copytree(repo_dir, dst_dir)
        for src_path, (labeled, unchanged) in results.items():
            if defense != "D4_prepend" and not unchanged:
                print(f"[preprocess]   WARNING: screener modified executable code in {src_path}")
            transformed = apply_variant(labeled, apply_key, lang="c")
            dst_path = Path(src_path.replace(str(repo_dir), str(dst_dir)))
            dst_path.write_text(transformed)

        print(f"[preprocess]   → {dst_dir.relative_to(DEMO_DIR)}")

    print(f"[preprocess] Done: {attacks_dst_root.relative_to(DEMO_DIR)}")


def main():
    parser = argparse.ArgumentParser(
        description="Sanitize demo attacked repos for D3L / D4_prepend defense runs."
    )
    parser.add_argument(
        "--defense", required=True, nargs="+", choices=["D3L", "D4_prepend"],
        help="Defense(es) to preprocess (D3L and/or D4_prepend)",
    )
    parser.add_argument(
        "--repo", nargs="+", default=["target_repo"],
        help="Repo name(s) under demo/ (default: target_repo)",
    )
    args = parser.parse_args()

    for defense in args.defense:
        for repo in args.repo:
            print(f"\n{'='*60}")
            print(f"[preprocess] Defense={defense}  Repo={repo}")
            print('='*60)
            process_repo(defense, repo)


if __name__ == "__main__":
    main()
