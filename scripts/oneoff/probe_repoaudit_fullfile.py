#!/usr/bin/env python3
"""
probe_repoaudit_fullfile.py

Authentic RepoAudit probe: run RepoAudit on the REAL full source file
(cloned at the fix commit), not our tree-sitter-extracted snippet. This gives
RepoAudit's metascan the whole file's NULL literals + call structure, which is
more faithful to its design than the snippet, without the whole-repo explosion.

Per slug it:
  1. reads cvebench/samples_cve_fix/<slug>/metadata.json (repo_url, commit, file, lang)
  2. shallow-fetches the repo at that commit into a clone cache
  3. runs RepoAuditDetector on the real full file
  4. prints verdict + whether the target function shows up in any reported bug

Long-running (clone + o3-mini calls) — run it yourself, not via Claude.
Set OPENAI_API_KEY (o3-mini). nvidia-smi not needed (API model).

Usage:
  python scripts/oneoff/probe_repoaudit_fullfile.py NPD-CVE-0006
  python scripts/oneoff/probe_repoaudit_fullfile.py NPD-CVE-0006 NPD-CVE-0027
"""
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))
sys.path.insert(0, str(REPO_ROOT / "cvebench"))
from splice_target import splice_function  # noqa: E402

SAMPLES = REPO_ROOT / "cvebench" / "samples_cve_fix"
CLONE_CACHE = Path("/tmp/cve_repos_fullfile")


def clone_at_commit(repo_url: str, commit: str, dest: Path) -> bool:
    """Shallow-fetch a single commit. Falls back to full clone + checkout."""
    if dest.exists() and any(dest.iterdir()):
        return True
    dest.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
        subprocess.run(["git", "remote", "add", "origin", repo_url], cwd=dest, check=True)
        subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", commit],
                       cwd=dest, check=True)
        subprocess.run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest, check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"  shallow fetch failed; trying full clone …", flush=True)
        subprocess.run(["rm", "-rf", str(dest)], check=False)
        try:
            subprocess.run(["git", "clone", "-q", repo_url, str(dest)], check=True)
            subprocess.run(["git", "checkout", "-q", commit], cwd=dest, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"  clone failed: {e}", flush=True)
            return False


def main() -> None:
    slugs = sys.argv[1:] or ["NPD-CVE-0006"]
    from detector_repoaudit import RepoAuditDetector

    for slug in slugs:
        print(f"\n{'='*60}\n{slug}\n{'='*60}", flush=True)
        meta_path = SAMPLES / slug / "metadata.json"
        if not meta_path.exists():
            print(f"  no metadata.json at {meta_path}"); continue
        meta = json.loads(meta_path.read_text())
        repo_url, commit = meta["repo_url"], meta["commit_hash"]
        rel_file, func, lang = meta["file"], meta["function"], meta.get("lang", "cpp")
        print(f"  repo={repo_url}@{commit[:10]}  file={rel_file}  fn={func}", flush=True)

        dest = CLONE_CACHE / slug
        if not clone_at_commit(repo_url, commit, dest):
            continue
        full_file = dest / rel_file
        if not full_file.exists():
            print(f"  target file not found in clone: {full_file}"); continue
        real_code = full_file.read_text(errors="replace")

        # Splice the benchmark's vulnerable target_function (attacker body +
        # ORIGINAL signature, so it's a clean drop-in) into ONLY this target
        # file, replacing the patched original. All other repo context untouched.
        bench = json.loads((REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
                            / f"repository_{slug}" / f"{slug}_CLEAN.json").read_text())
        vuln_fn = (bench[0] if isinstance(bench, list) else bench)["target_function"]
        code, n = splice_function(real_code, func, vuln_fn, lang)
        if n != 1:
            print(f"  SPLICE WARNING: replaced {n} definitions of '{func}' "
                  f"(expected exactly 1) — skipping" if n == 0 else
                  f"  SPLICE WARNING: replaced {n} definitions of '{func}' (expected 1)")
            if n == 0:
                continue
        print(f"  spliced vulnerable fn into target file: {len(code.splitlines())} lines "
              f"(was {len(real_code.splitlines())})", flush=True)

        # Match the proven snippet-run convention (the 16 TPs): write as
        # solution.c with glob *.c under language="Cpp". RepoAudit parses C++
        # content in a .c file under Cpp fine; a .cc/*.cc override made metascan
        # find 0 functions -> instant false "safe".
        # RepoAudit only registers a 'Cpp' NPD checker (no 'C' key -> KeyError);
        # its Cpp analyzer parses C fine, and the 16-TP snippet runs all used Cpp.
        ra_lang = "Cpp"
        glob = "*.c"
        fname = "solution.c"

        det = RepoAuditDetector(model_name="o3-mini", language=ra_lang, files=glob)
        # Feed the spliced full file as the whole code.
        record = {"target_function": code, "context_before": "", "context_after": "",
                  "auxiliary_file": "", "file_name": fname, "function_name": func}
        out = det.detect(record)
        reasoning = out.get("reasoning", "")
        # Sanity: how much analysis actually ran. Few calls + fast = simple paths,
        # not necessarily wrong — confirm a bug was still found if expected.
        n_explorer = reasoning.count("IntraDataFlowAnalyzer is invoked")
        n_validator = reasoning.count("PathValidator is invoked")
        n_sources = reasoning.count("[EXPLORER] Analyzing")
        found_in_target = func in reasoning  # crude targeting check
        print(f"  VERDICT: {out['verdict']}", flush=True)
        print(f"  sources analyzed: {n_sources} | Explorer(IntraDataFlow) calls: {n_explorer} "
              f"| Validator(PathValidator) calls: {n_validator}", flush=True)
        print(f"  target fn '{func}' mentioned in reasoning: {found_in_target}", flush=True)
        print(f"  reasoning tail:\n{reasoning[-600:]}", flush=True)


if __name__ == "__main__":
    main()
