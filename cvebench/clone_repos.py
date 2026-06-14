#!/usr/bin/env python3
"""
Re-clone the repos needed for patch_and_test on a new server.

Reads repo_url + commit_hash from samples_cve_fix/<pid>/metadata.json
for all viable samples (those with repo_testsuite_pass + task.md).
Clones each repo once (deduped by slug) into --clone-dir.

Usage:
  python3 cvebench/clone_repos.py \
      --ids-file cvebench/viable_184.txt \
      --samples-dir cvebench/samples_cve_fix \
      --clone-dir /tmp/cve_repos_fix
"""

import json
import shutil
import subprocess
from pathlib import Path

HERE           = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve_fix"
DEFAULT_CLONE   = Path("/tmp/cve_repos_fix")


def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


def clone_repo(url: str, commit: str, clone_dir: Path) -> bool:
    dest = clone_dir / repo_slug(url)
    if (dest / ".git").exists():
        print(f"  [cached] {url}")
        return True

    print(f"  Cloning {url} …")
    r = subprocess.run(
        ["git", "clone", "--filter=blob:none", url, str(dest)],
        capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:
        print(f"    FAIL: {r.stderr.splitlines()[0][:120] if r.stderr else '?'}")
        shutil.rmtree(dest, ignore_errors=True)
        return False

    for ref in [commit, "HEAD"]:
        r = subprocess.run(["git", "-C", str(dest), "checkout", ref],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            print(f"    checked out {ref}")
            return True

    print(f"    WARN: could not checkout {commit}, left at HEAD")
    return True


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Clone repos needed for patch_and_test")
    ap.add_argument("--ids-file",    default=str(HERE / "viable_184.txt"))
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES))
    ap.add_argument("--clone-dir",   default=str(DEFAULT_CLONE))
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    clone_dir   = Path(args.clone_dir)
    clone_dir.mkdir(parents=True, exist_ok=True)

    pids = [l.strip() for l in Path(args.ids_file).read_text().splitlines() if l.strip()]

    # Deduplicate by repo slug
    seen: dict[str, tuple[str, str]] = {}  # slug → (url, commit)
    for pid in pids:
        meta_path = samples_dir / pid / "metadata.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text())
        url    = meta.get("repo_url", "")
        commit = meta.get("commit_hash", "HEAD")
        slug   = repo_slug(url)
        if url and slug not in seen:
            seen[slug] = (url, commit)

    print(f"Cloning {len(seen)} repos → {clone_dir}\n")
    ok = sum(clone_repo(url, commit, clone_dir) for url, commit in seen.values())
    print(f"\n{ok}/{len(seen)} repos ready")


if __name__ == "__main__":
    main()
