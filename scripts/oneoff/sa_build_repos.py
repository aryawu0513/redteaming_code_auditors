"""
Build all 128 CVE repos in-place (cve_repos_fix) so that generated headers
and compile_commands.json are available for Clang SA.

For cmake repos:
  - Runs cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON into <repo>/_cmake_build/
  - cmake generates compile_commands.json automatically
  - Then does a full build to produce config.h and other generated headers

For autoconf/make repos:
  - Runs autoreconf + ./configure to generate config.h etc.
  - Runs bear -- make to intercept compiler calls → compile_commands.json
  - Falls back to make -k (no bear) if bear not available

For other repos:
  - Tries bear -- make as a generic fallback

Usage:
    python scripts/oneoff/sa_build_repos.py [--resume] [--slug NPD-CVE-0006]

Output:
    Builds in-place in /mnt/ssd/aryawu/cve_repos_fix/<repo>/
    compile_commands.json written to <repo>/_cmake_build/ or <repo>/
    Summary written to results/sa_build_repos.json
"""

import argparse
import json
import subprocess
import shutil
from pathlib import Path

MANIFEST  = Path("/mnt/ssd/aryawu/cve_repos_fix/clone_manifest.json")
OUT_PATH  = Path("/mnt/ssd/aryawu/redteaming_code_auditors/results/sa_build_repos.json")
CMAKE     = "cmake"
BEAR      = shutil.which("bear")
BUILD_TIMEOUT = 300   # seconds per repo


def _run(cmd, cwd, timeout=BUILD_TIMEOUT):
    try:
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def build_repo(repo_path: Path) -> dict:
    """Build a repo in-place. Returns status dict."""
    result = {"repo": repo_path.name, "compile_commands": None, "built": False, "method": None}

    # ── cmake ────────────────────────────────────────────────────────────────
    if (repo_path / "CMakeLists.txt").exists():
        build_dir = repo_path / "_cmake_build"
        build_dir.mkdir(exist_ok=True)
        r = _run([CMAKE, "-S", str(repo_path), "-B", str(build_dir),
                  "-DCMAKE_BUILD_TYPE=Debug",
                  "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",   # generates compile_commands.json
                  "--no-warn-unused-cli"],
                 cwd=repo_path, timeout=120)
        cc = build_dir / "compile_commands.json"
        if cc.exists():
            result["compile_commands"] = str(cc)

        r2 = _run([CMAKE, "--build", str(build_dir), "--parallel", "4"],
                  cwd=repo_path, timeout=BUILD_TIMEOUT)
        result["built"]  = r2 is not None and r2.returncode == 0
        result["method"] = "cmake"
        result["rc"]     = r2.returncode if r2 else "timeout"
        return result

    # ── autoconf + make ──────────────────────────────────────────────────────
    if (repo_path / "configure.ac").exists() or (repo_path / "configure").exists():
        if (repo_path / "configure.ac").exists() and not (repo_path / "configure").exists():
            _run(["autoreconf", "-fi"], cwd=repo_path, timeout=120)
        if (repo_path / "autogen.sh").exists():
            _run(["bash", "autogen.sh"], cwd=repo_path, timeout=120)
        if (repo_path / "configure").exists():
            _run(["./configure", "--quiet"], cwd=repo_path, timeout=180)

        # bear intercepts compiler calls → compile_commands.json
        if BEAR:
            r = _run([BEAR, "--", "make", "-j4", "-k", "--keep-going"],
                     cwd=repo_path, timeout=BUILD_TIMEOUT)
        else:
            r = _run(["make", "-j4", "-k", "--keep-going"],
                     cwd=repo_path, timeout=BUILD_TIMEOUT)

        cc = repo_path / "compile_commands.json"
        if cc.exists():
            result["compile_commands"] = str(cc)
        result["built"]  = r is not None and r.returncode == 0
        result["method"] = "autoconf+bear" if (BEAR and cc.exists()) else "autoconf"
        result["rc"]     = r.returncode if r else "timeout"
        return result

    # ── plain make ───────────────────────────────────────────────────────────
    if (repo_path / "Makefile").exists():
        if BEAR:
            r = _run([BEAR, "--", "make", "-j4", "-k", "--keep-going"],
                     cwd=repo_path, timeout=BUILD_TIMEOUT)
        else:
            r = _run(["make", "-j4", "-k", "--keep-going"],
                     cwd=repo_path, timeout=BUILD_TIMEOUT)
        cc = repo_path / "compile_commands.json"
        if cc.exists():
            result["compile_commands"] = str(cc)
        result["built"]  = r is not None
        result["method"] = "make+bear" if (BEAR and cc.exists()) else "make"
        result["rc"]     = r.returncode if r else "timeout"
        return result

    result["method"] = "none"
    result["error"]  = "no build system found"
    return result


def find_compile_commands(repo_path: Path) -> Path | None:
    """Find the compile_commands.json for a repo (cmake build dir or root)."""
    for candidate in [repo_path / "_cmake_build" / "compile_commands.json",
                      repo_path / "compile_commands.json"]:
        if candidate.exists():
            return candidate
    return None


def get_flags_for_file(compile_commands: Path, target_file: Path) -> list[str]:
    """Extract compile flags for a specific file from compile_commands.json."""
    entries = json.loads(compile_commands.read_text())
    target_name = target_file.name
    target_str  = str(target_file)

    # Try exact match first, then basename match
    entry = None
    for e in entries:
        if e.get("file") == target_str or target_str.endswith(e.get("file", "")):
            entry = e
            break
    if entry is None:
        for e in entries:
            if target_name == Path(e.get("file", "")).name:
                entry = e
                break
    if entry is None:
        return []

    build_dir = Path(entry.get("directory", str(compile_commands.parent)))
    flags = []
    parts = entry["command"].split()
    i = 0
    while i < len(parts):
        p = parts[i]
        if p.startswith("-I"):
            inc = p[2:] or (parts[i+1] if i+1 < len(parts) else "")
            if not Path(inc).is_absolute():
                inc = str(build_dir / inc)
            flags += ["-I", inc]
            if not p[2:]: i += 1
        elif p == "-I" and i+1 < len(parts):
            inc = parts[i+1]
            if not Path(inc).is_absolute():
                inc = str(build_dir / inc)
            flags += ["-I", inc]
            i += 1
        elif p.startswith("-D") or p.startswith("-std") or p.startswith("-f"):
            flags.append(p)
        elif p == "-D" and i+1 < len(parts):
            flags += ["-D", parts[i+1]]
            i += 1
        i += 1
    return flags


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true",
                        help="Skip repos that already have compile_commands.json")
    parser.add_argument("--slug", nargs="*", help="Only build these slugs")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())

    # Deduplicate by clone_dir (multiple slugs may share a repo)
    by_repo: dict[str, list[str]] = {}
    for slug, m in manifest.items():
        cd = m.get("clone_dir", "")
        if cd:
            by_repo.setdefault(cd, []).append(slug)

    if args.slug:
        keep = set(args.slug)
        by_repo = {cd: slugs for cd, slugs in by_repo.items()
                   if any(s in keep for s in slugs)}

    results = {}
    if OUT_PATH.exists():
        results = {r["repo"]: r for r in json.loads(OUT_PATH.read_text())}

    total = len(by_repo)
    done  = 0
    print(f"Building {total} unique repos (bear={'available' if BEAR else 'NOT FOUND — no compile_commands for make repos'})")
    print()

    for clone_dir, slugs in sorted(by_repo.items()):
        repo_path = Path(clone_dir)
        repo_key  = repo_path.name
        done += 1

        if args.resume and find_compile_commands(repo_path):
            cc = find_compile_commands(repo_path)
            results[repo_key] = {"repo": repo_key, "compile_commands": str(cc),
                                 "built": True, "method": "cached"}
            print(f"  [{done}/{total}] {repo_key}  → cached ({cc.name})")
            continue

        print(f"  [{done}/{total}] {repo_key}  (slugs: {', '.join(slugs)})")
        r = build_repo(repo_path)
        results[repo_key] = r
        cc_status = Path(r["compile_commands"]).name if r.get("compile_commands") else "none"
        print(f"    → method={r['method']}  built={r.get('built')}  rc={r.get('rc','?')}  cc={cc_status}")

        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUT_PATH.write_text(json.dumps(list(results.values()), indent=2))

    # Summary
    with_cc  = sum(1 for r in results.values() if r.get("compile_commands"))
    built_ok = sum(1 for r in results.values() if r.get("built"))
    by_method = {}
    for r in results.values():
        by_method[r.get("method","?")] = by_method.get(r.get("method","?"), 0) + 1

    print(f"""
=== Build Summary ({len(results)} repos) ===
  compile_commands.json generated : {with_cc}/{len(results)}
  full build succeeded            : {built_ok}/{len(results)}
  by method: {by_method}
Results → {OUT_PATH}""")


if __name__ == "__main__":
    main()
