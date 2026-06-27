"""
Create git worktrees for Infer and CodeQL SA runs so all three tools
can run in parallel without conflicting on the same repo files.

CppCheck  → uses /mnt/ssd/aryawu/cve_repos_fix/  (original, already there)
Infer     → uses /mnt/ssd/aryawu/cve_repos_infer/  (worktrees created here)
CodeQL    → uses /mnt/ssd/aryawu/cve_repos_codeql/ (worktrees created here)

git worktree shares the .git object store — no re-download, minimal extra disk.
Each working tree is a separate checkout so file patches don't cross-contaminate.

Usage:
    python scripts/oneoff/sa_setup_worktrees.py
    python scripts/oneoff/sa_setup_worktrees.py --remove   # clean up worktrees
"""

import argparse
import json
import subprocess
from pathlib import Path
from collections import OrderedDict

MANIFEST_PATH  = Path("/mnt/ssd/aryawu/cve_repos_fix/clone_manifest.json")
ORIGINAL_ROOT  = Path("/mnt/ssd/aryawu/cve_repos_fix")
INFER_ROOT     = Path("/mnt/ssd/aryawu/cve_repos_infer")
CODEQL_ROOT    = Path("/mnt/ssd/aryawu/cve_repos_codeql")

INFER_MANIFEST_PATH  = Path("/mnt/ssd/aryawu/cve_repos_infer/clone_manifest.json")
CODEQL_MANIFEST_PATH = Path("/mnt/ssd/aryawu/cve_repos_codeql/clone_manifest.json")


def get_unique_repos(manifest: dict) -> dict[str, str]:
    """Return {clone_dir: clone_dir} deduplicated by clone_dir."""
    seen = OrderedDict()
    for m in manifest.values():
        cd = m["clone_dir"]
        if cd not in seen:
            seen[cd] = cd
    return seen


def add_worktree(source_repo: Path, worktree_path: Path) -> bool:
    if worktree_path.exists():
        return True  # already done
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "-C", str(source_repo), "worktree", "add",
         "--detach", str(worktree_path), "HEAD"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  [FAIL] {source_repo.name}: {r.stderr.strip()}")
        return False
    return True


def remove_worktree(source_repo: Path, worktree_path: Path):
    subprocess.run(
        ["git", "-C", str(source_repo), "worktree", "remove",
         "--force", str(worktree_path)],
        capture_output=True
    )


def build_manifest(original_manifest: dict, new_root: Path) -> dict:
    """Rewrite clone_dir paths in the manifest to point to new_root."""
    new_manifest = {}
    for slug, m in original_manifest.items():
        orig_dir = Path(m["clone_dir"])
        new_dir  = new_root / orig_dir.name
        new_manifest[slug] = {**m, "clone_dir": str(new_dir)}
    return new_manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remove", action="store_true",
                        help="Remove worktrees instead of creating them")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text())
    unique_repos = get_unique_repos(manifest)
    print(f"{'Removing' if args.remove else 'Creating'} worktrees for "
          f"{len(unique_repos)} unique repos...")

    ok = fail = 0
    for orig_clone_dir in unique_repos:
        source = Path(orig_clone_dir)
        repo_name = source.name
        infer_wt  = INFER_ROOT  / repo_name
        codeql_wt = CODEQL_ROOT / repo_name

        if args.remove:
            remove_worktree(source, infer_wt)
            remove_worktree(source, codeql_wt)
            print(f"  removed {repo_name}")
            ok += 1
        else:
            i_ok = add_worktree(source, infer_wt)
            c_ok = add_worktree(source, codeql_wt)
            status = "ok" if (i_ok and c_ok) else "PARTIAL"
            print(f"  [{status}] {repo_name}")
            if i_ok and c_ok:
                ok += 1
            else:
                fail += 1

    if not args.remove:
        # Write manifests pointing to the new roots
        infer_manifest  = build_manifest(manifest, INFER_ROOT)
        codeql_manifest = build_manifest(manifest, CODEQL_ROOT)
        INFER_MANIFEST_PATH.write_text(json.dumps(infer_manifest, indent=2))
        CODEQL_MANIFEST_PATH.write_text(json.dumps(codeql_manifest, indent=2))
        print(f"\nManifests written:")
        print(f"  {INFER_MANIFEST_PATH}")
        print(f"  {CODEQL_MANIFEST_PATH}")

    print(f"\nDone: {ok} ok, {fail} failed")


if __name__ == "__main__":
    main()
