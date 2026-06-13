#!/usr/bin/env python3
"""
Extract local headers needed by each CVE sample and save as raw_headers.h.

For each sample, parses #include "..." directives from raw_primary.cc and
raw_auxiliary.cc, resolves them relative to the source file's location in the
repo clone, recursively follows one level of includes, and concatenates all
found headers into samples_cve_fix/<pid>/raw_headers.h.

System headers (<...>) are ignored — only project-local headers ("...") matter.

Usage:
  python3 repo_cve_dataset_mining_new/extract_headers.py \\
      repo_cve_dataset_mining_new/f3_nolimit_dedup_func.jsonl \\
      --ids-file repo_cve_dataset_mining_new/viable_184.txt \\
      --samples-dir repo_cve_dataset_mining_new/samples_cve_fix \\
      --clone-dir /tmp/cve_repos_fix
"""

import json
import re
from pathlib import Path

HERE           = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve_fix"
DEFAULT_CLONE   = Path("/tmp/cve_repos_fix")

MAX_HEADER_CHARS = 120_000  # cap total headers to ~30K tokens


def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


def parse_local_includes(src: str) -> list[str]:
    """Return all #include "..." paths from src (not system includes)."""
    return re.findall(r'#\s*include\s+"([^"]+)"', src)


def resolve_header(inc_path: str, src_file_dir: Path, repo_root: Path) -> Path | None:
    """Try to find a header file, searching relative to source dir then repo root."""
    for base in [src_file_dir, repo_root]:
        candidate = (base / inc_path).resolve()
        try:
            candidate.relative_to(repo_root.resolve())
        except ValueError:
            continue
        if candidate.exists():
            return candidate
    return None


def collect_headers(src: str, src_file_dir: Path, repo_root: Path,
                    seen: set[Path], depth: int = 0) -> list[tuple[Path, str]]:
    """Recursively collect (path, content) for local headers up to depth 2."""
    results = []
    for inc in parse_local_includes(src):
        path = resolve_header(inc, src_file_dir, repo_root)
        if path is None or path in seen:
            continue
        seen.add(path)
        try:
            content = path.read_text(errors="replace")
        except OSError:
            continue
        results.append((path, content))
        if depth < 1:
            results.extend(collect_headers(content, path.parent, repo_root, seen, depth + 1))
    return results


def process_one(pid: str, meta: dict, samples_dir: Path, clone_dir: Path,
                force: bool) -> str:
    sample_dir  = samples_dir / pid
    out_path    = sample_dir / "raw_headers.h"

    if not force and out_path.exists():
        return "skip"

    file_path = meta.get("file_path") or meta.get("file", "")
    repo_url  = meta.get("repo_url", "")
    slug      = repo_slug(repo_url)
    repo_root = clone_dir / slug

    if not repo_root.exists():
        return "skip_no_clone"

    src_file_dir = (repo_root / file_path).parent

    # Collect includes from primary + auxiliary
    sources = []
    primary_path = sample_dir / "raw_primary.cc"
    if primary_path.exists():
        sources.append(primary_path.read_text(errors="replace"))
    aux_path = sample_dir / "raw_auxiliary.cc"
    if aux_path.exists():
        sources.append(aux_path.read_text(errors="replace"))

    if not sources:
        return "skip_no_source"

    seen: set[Path] = set()
    all_headers: list[tuple[Path, str]] = []
    for src in sources:
        all_headers.extend(collect_headers(src, src_file_dir, repo_root, seen))

    if not all_headers:
        return "no_headers"

    # Concatenate, cap at MAX_HEADER_CHARS total
    parts = []
    total = 0
    for path, content in all_headers:
        rel = path.relative_to(repo_root)
        header_block = f"/* === {rel} === */\n{content}\n"
        if total + len(header_block) > MAX_HEADER_CHARS:
            parts.append(f"/* ... remaining headers truncated (size limit) ... */\n")
            break
        parts.append(header_block)
        total += len(header_block)

    out_path.write_text("".join(parts))
    return f"ok ({len(all_headers)} headers, {total} chars)"


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Extract local headers for each CVE sample")
    ap.add_argument("jsonl")
    ap.add_argument("ids",          nargs="*")
    ap.add_argument("--ids-file",   help="File with one pilot ID per line")
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES))
    ap.add_argument("--clone-dir",   default=str(DEFAULT_CLONE))
    ap.add_argument("--force",       action="store_true")
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    clone_dir   = Path(args.clone_dir)

    rows = {json.loads(l)["pilot_id"]: json.loads(l)
            for l in Path(args.jsonl).read_text().splitlines() if l.strip()}

    if args.ids_file:
        pids = [l.strip() for l in Path(args.ids_file).read_text().splitlines() if l.strip()]
        pids = [p for p in pids if p in rows]
    elif args.ids:
        pids = [p for p in args.ids if p in rows]
    else:
        pids = list(rows.keys())

    print(f"Extracting headers for {len(pids)} samples\n")
    from collections import Counter
    counts: Counter = Counter()
    for pid in pids:
        status = process_one(pid, rows[pid], samples_dir, clone_dir, args.force)
        counts[status.split()[0]] += 1
        if not status.startswith("skip"):
            print(f"  {pid}: {status}")

    print(f"\nDone: {dict(counts)}")


if __name__ == "__main__":
    main()
