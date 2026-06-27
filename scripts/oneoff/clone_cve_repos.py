#!/usr/bin/env python3
"""
clone_cve_repos.py

Re-clone the CVE repos for cvebench_full at their fix commits, deduped by
(repo_url, commit_hash) so each commit is fetched once even when several slugs
share it. Shallow-fetches a single commit (small, fast); falls back to a full
clone + checkout if the host won't serve the bare SHA.

Persisted OUTSIDE /tmp so they survive (default /mnt/ssd/aryawu/cve_repos_fix),
override with CLONE_ROOT. Resumable: skips clones whose target file already
exists. Writes clone_manifest.json mapping slug -> {clone_dir, file, function,
lang, repo_url, commit} for downstream consumers (RepoAudit full-file probe,
VulWeaver reformat).

Long-running I/O — run it yourself (tmux), not via Claude.

Usage:
  python scripts/oneoff/clone_cve_repos.py            # all cvebench_full slugs
  CLONE_ROOT=/data/clones WORKERS=8 python scripts/oneoff/clone_cve_repos.py
"""
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
SAMPLES = REPO_ROOT / "cvebench" / "samples_cve_fix"
CLONE_ROOT = Path(os.getenv("CLONE_ROOT", "/mnt/ssd/aryawu/cve_repos_fix"))
WORKERS = int(os.getenv("WORKERS", "6"))


def repo_dirname(repo_url: str, commit: str) -> str:
    slug = re.sub(r"^https?://github\.com/", "", repo_url.rstrip("/"))
    slug = slug.replace("/", "__").replace(".git", "")
    return f"{slug}__{commit[:10]}"


def clone_one(repo_url: str, commit: str, dest: Path, sentinel_file: str) -> tuple[bool, str]:
    if (dest / sentinel_file).exists():
        return True, "exists"
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=False)
    dest.mkdir(parents=True, exist_ok=True)
    # Shallow single-commit fetch.
    try:
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
        subprocess.run(["git", "remote", "add", "origin", repo_url], cwd=dest, check=True)
        subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", commit],
                       cwd=dest, check=True, timeout=900)
        subprocess.run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest, check=True)
        return True, "shallow"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    # Fallback: full clone + checkout.
    subprocess.run(["rm", "-rf", str(dest)], check=False)
    try:
        subprocess.run(["git", "clone", "-q", repo_url, str(dest)], check=True, timeout=1800)
        subprocess.run(["git", "checkout", "-q", commit], cwd=dest, check=True)
        return True, "full"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return False, f"FAIL {e}"


def main() -> None:
    slugs = sorted(p.name.replace("repository_", "") for p in BASELINE.glob("repository_*"))
    print(f"cvebench_full slugs: {len(slugs)}")

    # slug -> metadata; dedup clone jobs by (repo, commit)
    slug_meta, jobs = {}, {}
    for slug in slugs:
        mp = SAMPLES / slug / "metadata.json"
        if not mp.exists():
            print(f"  [skip] {slug}: no metadata.json"); continue
        m = json.loads(mp.read_text())
        commit = m.get("commit_hash")
        if not commit or commit == "None":
            print(f"  [skip] {slug}: no commit_hash"); continue
        d = repo_dirname(m["repo_url"], commit)
        slug_meta[slug] = {**m, "clone_dir": str(CLONE_ROOT / d)}
        jobs[(m["repo_url"], commit)] = CLONE_ROOT / d

    print(f"unique (repo,commit) clone jobs: {len(jobs)}  → {CLONE_ROOT}")
    CLONE_ROOT.mkdir(parents=True, exist_ok=True)

    results = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(clone_one, ru, c, dest, "/.git/HEAD".lstrip("/")): (ru, c, dest)
                for (ru, c), dest in jobs.items()}
        done = 0
        for fut in as_completed(futs):
            ru, c, dest = futs[fut]
            ok, how = fut.result()
            results[(ru, c)] = ok
            done += 1
            print(f"  [{done}/{len(jobs)}] {'OK ' if ok else 'ERR'} ({how}) {dest.name}", flush=True)

    # Verify target file present per slug; write manifest.
    manifest, missing_file = {}, []
    for slug, m in slug_meta.items():
        cdir = Path(m["clone_dir"])
        fpath = cdir / m["file"]
        present = fpath.exists()
        if not present:
            missing_file.append(slug)
        manifest[slug] = {
            "clone_dir": m["clone_dir"], "file": m["file"], "function": m["function"],
            "lang": m.get("lang", "cpp"), "repo_url": m["repo_url"],
            "commit": m["commit_hash"], "file_present": present,
        }
    man_path = CLONE_ROOT / "clone_manifest.json"
    man_path.write_text(json.dumps(manifest, indent=2))

    ok_clones = sum(1 for v in results.values() if v)
    print(f"\nClones: {ok_clones}/{len(jobs)} succeeded")
    print(f"Slugs with target file present: {len(slug_meta)-len(missing_file)}/{len(slug_meta)}")
    if missing_file:
        print(f"  target file MISSING for {len(missing_file)}: {missing_file[:15]}")
    print(f"Manifest: {man_path}")


if __name__ == "__main__":
    main()
