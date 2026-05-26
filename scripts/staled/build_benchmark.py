#!/usr/bin/env python3
"""
build_benchmark.py — Build the unified benchmark/ directory from existing per-system
dataset dirs.  Safe to re-run; overwrites nothing if output already exists unless
--force is passed.

Produces:
  benchmark/handcraft/{category}/{variant}/
      {variant}_{ATTACK}.c     — raw C files (RepoAudit reads these)
      {variant}_{ATTACK}.json  — unified JSON (VulnLLM-R, VulTrial, OpenVul read these)

  benchmark/leetcodebench_gpt54mini/{category}/{slug}/
      solution.c               — clean baseline
      solution_{ATTACK}.c      — attacked variants
      {slug}_CLEAN.json
      {slug}_{ATTACK}.json

JSON schema (superset of all systems):
  code, context, target_function, function_name, file_name,
  CWE_ID, RELATED_CWE, stack_trace, target, language, dataset, idx
"""

import argparse
import json
import re
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
OUT_ROOT  = REPO_ROOT / "benchmark"

# ── Handcraft sources ──────────────────────────────────────────────────────────
RA_BENCH  = REPO_ROOT / "RepoAudit/benchmark/C/NPD"   # .c files
VL_DATA   = REPO_ROOT / "VulnLLM-R/datasets/C/NPD"   # JSON with 'code' field
OV_DATA   = REPO_ROOT / "OpenVul/datasets/C/NPD"      # JSON with context/target split

# Categories that exist in the handcraft benchmark
HC_CATEGORIES = ["baseline", "context_aware"]

# ── LeetCode attacker sources ──────────────────────────────────────────────────
ATTACKER_DATA = REPO_ROOT / "attacker/datasets/C/NPD/attacker_lcb"
LC_CATEGORIES = ["context_aware", "baseline"]

# Slugs excluded from evaluation (wrong algorithm or no pointer operations)
LC_EXCLUDED = {"E9FB59F8273B", "F4FB78BE2FBB"}

MAIN_RE = re.compile(r'^(?:int|void)\s+main\s*\(', re.MULTILINE)


def split_code(code: str) -> tuple[str, str]:
    """Split '// context\n...\n\n// target function\n...' into (context, target)."""
    # Try explicit comment markers first
    if "// context" in code and "// target function" in code:
        parts = re.split(r'\n\n// target function\n', code, maxsplit=1)
        if len(parts) == 2:
            ctx = re.sub(r'^// context\n', '', parts[0])
            return ctx.strip(), parts[1].strip()
    # Fall back: split at main()
    m = MAIN_RE.search(code)
    if m:
        return code[:m.start()].strip(), code[m.start():].strip()
    return "", code.strip()


def merge_json(vl_entry: dict, ov_entry: dict | None, c_file: Path) -> dict:
    """Merge VulnLLM-R + OpenVul entries into a unified superset record."""
    code = vl_entry.get("code", "")
    if ov_entry:
        context        = ov_entry.get("context", "")
        target_function = ov_entry.get("target_function", "")
        function_name  = ov_entry.get("function_name", "")
        file_name      = ov_entry.get("file_name", c_file.name)
    else:
        context, target_function = split_code(code)
        function_name = "main"
        file_name     = c_file.name

    return {
        "code":            code,
        "context":         context,
        "target_function": target_function,
        "function_name":   function_name,
        "file_name":       file_name,
        "CWE_ID":          vl_entry.get("CWE_ID", ["CWE-476"]),
        "RELATED_CWE":     vl_entry.get("RELATED_CWE", []),
        "stack_trace":     vl_entry.get("stack_trace", ""),
        "target":          vl_entry.get("target", 1),
        "language":        "c",
        "dataset":         vl_entry.get("dataset", "handcraft"),
        "idx":             vl_entry.get("idx", 0),
    }


def load_json_dir(d: Path) -> dict[str, dict]:
    """Return stem -> first entry for each *.json in directory d."""
    result = {}
    if not d.exists():
        return result
    for p in d.glob("*.json"):
        try:
            data = json.loads(p.read_text())
            if isinstance(data, list) and data:
                result[p.stem] = data[0]
        except Exception:
            pass
    return result


def build_handcraft(force: bool) -> None:
    print("── handcraft ──────────────────────────────────────────────────────")
    for category in HC_CATEGORIES:
        ra_cat = RA_BENCH / category
        if not ra_cat.exists():
            continue
        for variant_dir in sorted(ra_cat.iterdir()):
            if not variant_dir.is_dir():
                continue
            variant = variant_dir.name
            out_dir = OUT_ROOT / "handcraft" / category / variant
            out_dir.mkdir(parents=True, exist_ok=True)

            # Load VulnLLM-R and OpenVul JSONs for this variant (old c/ path)
            vl_entries = load_json_dir(VL_DATA / category / variant / "c")
            ov_entries = load_json_dir(OV_DATA / category / variant / "c")

            for c_file in sorted(variant_dir.glob("*.c")):
                out_c = out_dir / c_file.name
                if force or not out_c.exists():
                    shutil.copy2(c_file, out_c)

                stem = c_file.stem  # e.g. findrec_COT
                out_json = out_dir / f"{stem}.json"
                if not force and out_json.exists():
                    continue

                vl = vl_entries.get(stem)
                ov = ov_entries.get(stem)
                if vl:
                    entry = merge_json(vl, ov, c_file)
                elif ov:
                    # OpenVul-only: reconstruct code field
                    code = f"// context\n{ov['context']}\n\n// target function\n{ov['target_function']}"
                    vl_stub = {"code": code, "CWE_ID": ["CWE-476"],
                               "RELATED_CWE": [], "stack_trace": "",
                               "target": 1, "language": "c",
                               "dataset": "handcraft", "idx": 0}
                    entry = merge_json(vl_stub, ov, c_file)
                else:
                    # No JSON source — build from .c file alone
                    code = c_file.read_text(errors="replace")
                    ctx, tgt = split_code(code)
                    entry = {
                        "code": code, "context": ctx,
                        "target_function": tgt, "function_name": "main",
                        "file_name": c_file.name, "CWE_ID": ["CWE-476"],
                        "RELATED_CWE": [], "stack_trace": "",
                        "target": 1, "language": "c",
                        "dataset": "handcraft", "idx": 0,
                    }

                out_json.write_text(json.dumps([entry], indent=2))

            n_c    = len(list(out_dir.glob("*.c")))
            n_json = len(list(out_dir.glob("*.json")))
            print(f"  {category}/{variant}: {n_c} .c  {n_json} .json")


def build_leetcodebench(force: bool) -> None:
    print("── leetcodebench ──────────────────────────────────────────────────")
    if not ATTACKER_DATA.exists():
        print("  attacker/datasets not found — skipping leetcodebench")
        return

    for slug_dir in sorted(ATTACKER_DATA.glob("repository_*")):
        slug = slug_dir.name.removeprefix("repository_")
        if slug in LC_EXCLUDED:
            continue
        json_src = slug_dir / "c"  # old layout

        for category in LC_CATEGORIES:
            # For context_aware: all attacked variants
            # For baseline: only solution.c (CLEAN)
            out_dir = OUT_ROOT / "leetcodebench_gpt54mini" / category / f"repository_{slug}"
            out_dir.mkdir(parents=True, exist_ok=True)

            # Copy .c files from the runs dir if available
            runs_dir = REPO_ROOT / "attacker/runs/gpt-5.4-mini" / f"repository_{slug}"
            if runs_dir.exists():
                pattern = "solution.c" if category == "baseline" else "solution*.c"
                for c_file in sorted(runs_dir.glob(pattern)):
                    out_c = out_dir / c_file.name
                    if force or not out_c.exists():
                        shutil.copy2(c_file, out_c)

            # Copy/upgrade JSON files from old attacker dataset
            if json_src.exists():
                for json_file in sorted(json_src.glob("*.json")):
                    # Determine if this belongs in baseline or context_aware
                    stem = json_file.stem  # e.g. 069A7F404506_COT
                    variant_part = stem[len(slug) + 1:] if "_" in stem[12:] else "CLEAN"
                    if category == "baseline" and variant_part != "CLEAN":
                        continue
                    if category == "context_aware" and variant_part == "CLEAN":
                        continue

                    out_json = out_dir / json_file.name
                    if not force and out_json.exists():
                        continue

                    try:
                        data = json.loads(json_file.read_text())
                        if not isinstance(data, list) or not data:
                            continue
                        e = data[0]
                        # Upgrade: ensure all fields present
                        code = e.get("code", "")
                        if not code and e.get("context") and e.get("target_function"):
                            code = f"// context\n{e['context']}\n\n// target function\n{e['target_function']}"
                        ctx = e.get("context", "")
                        tgt = e.get("target_function", "")
                        if not ctx and code:
                            ctx, tgt = split_code(code)
                        upgraded = {
                            "code":            code,
                            "context":         ctx,
                            "target_function": tgt,
                            "function_name":   e.get("function_name", "main"),
                            "file_name":       e.get("file_name", json_file.stem + ".c"),
                            "CWE_ID":          e.get("CWE_ID", ["CWE-476"]),
                            "RELATED_CWE":     e.get("RELATED_CWE", []),
                            "stack_trace":     e.get("stack_trace", ""),
                            "target":          e.get("target", 1),
                            "language":        "c",
                            "dataset":         "leetcodebench",
                            "idx":             e.get("idx", 0),
                            "slug":            e.get("slug", slug),
                            "variant":         e.get("variant", variant_part),
                        }
                        out_json.write_text(json.dumps([upgraded], indent=2))
                    except Exception as ex:
                        print(f"  [warn] {json_file}: {ex}")

            n_c    = len(list(out_dir.glob("*.c")))
            n_json = len(list(out_dir.glob("*.json")))
            if n_c + n_json:
                print(f"  {category}/repository_{slug}: {n_c} .c  {n_json} .json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build unified benchmark/ directory")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing files")
    parser.add_argument("--handcraft-only", action="store_true")
    parser.add_argument("--leetcode-only",  action="store_true")
    args = parser.parse_args()

    do_hc = not args.leetcode_only
    do_lc = not args.handcraft_only

    if do_hc:
        build_handcraft(args.force)
    if do_lc:
        build_leetcodebench(args.force)

    print(f"\nDone → {OUT_ROOT}")


if __name__ == "__main__":
    main()
