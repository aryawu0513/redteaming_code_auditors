#!/usr/bin/env python3
"""
build_benchmark.py — Stage 3: build the final CVE NPD benchmark from judge output.

Takes the 128 verified vulnerable samples from judge_r1r2.jsonl, splices
the attacker's function body into starter.cc, splits into context + target_function,
and writes to benchmark/cvebench_full/baseline/repository_<pid>/<pid>_CLEAN.json
in the schema used by VulnLLM-R, OpenVul, and the adaptive attacker.

Usage:
  python3 repo_cve_dataset_mining_new/build_benchmark.py \\
      --judge   repo_cve_dataset_mining_new/judge_r1r2.jsonl \\
      --dataset repo_cve_dataset_mining_new/f3_nolimit_dedup_func.slim.jsonl \\
      --samples repo_cve_dataset_mining_new/samples_cve_fix \\
      --rounds  repo_cve_dataset_mining_new/rounds \\
      --out-root benchmark/cvebench_full \\
      [--only-rounds r1 r2] [--dataset-tag cvebench_full]
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from repo_cve_dataset_mining_new.patch_and_test import extract_body, splice_body

REPO_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def strip_npd_marker(code: str) -> str:
    return "\n".join(l for l in code.splitlines() if "/* NPD site */" not in l)


def extract_attacker_npd_line(code: str) -> str:
    lines = code.splitlines()
    for i, line in enumerate(lines):
        if "/* NPD site */" in line:
            for j in range(i + 1, len(lines)):
                stripped = lines[j].strip()
                if stripped:
                    return stripped
    return ""


def split_file(code: str, func_name: str) -> tuple[str, str]:
    """Split code into (context, target_function) at func_name's definition."""
    pattern = re.compile(
        r'^\s*'
        r'(?:(?:static|inline|explicit|virtual|override|extern)\s+)*'
        r'(?:\w[\w\s:*&<>]*?\s+)?'
        r'(?:\w[\w:]*::)*'
        + re.escape(func_name) + r'\s*\(',
        re.MULTILINE,
    )
    m = pattern.search(code)
    if not m:
        return code.rstrip(), ""
    return code[:m.start()].rstrip(), code[m.start():]


def npd_site_match(a: str, g: str) -> bool:
    a, g = (a or "").strip(), (g or "").strip()
    if not a or a == "none" or not g or g in ("none", "null"):
        return False
    return a == g or a in g or g in a


def find_best_output(pid: str, rounds_dir: Path,
                     only_rounds: set[str] | None = None) -> Path | None:
    rounds = sorted(rounds_dir.iterdir(), key=lambda p: p.name)
    if only_rounds:
        rounds = [r for r in rounds if r.name in only_rounds]
    best_pass = best_partial = best_any = None
    for rd in rounds:
        out    = rd / pid / "attacker_output.cc"
        result = rd / pid / "attacker_result.json"
        if not out.exists():
            continue
        best_any = out
        if result.exists():
            v = json.loads(result.read_text()).get("verdict", "")
            if v == "pass":
                best_pass = out
            elif v == "partial":
                best_partial = out
    return best_pass or best_partial or best_any


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--judge",       required=True)
    ap.add_argument("--dataset",     required=True)
    ap.add_argument("--samples",     required=True)
    ap.add_argument("--rounds",      required=True)
    ap.add_argument("--out-root",    required=True)
    ap.add_argument("--only-rounds", nargs="*", default=["r1", "r2"])
    ap.add_argument("--dataset-tag", default="cve-npd-bench")
    args = ap.parse_args()

    only_rounds = set(args.only_rounds)
    samples_dir = Path(args.samples)
    rounds_dir  = Path(args.rounds)
    out_root    = REPO_ROOT / args.out_root

    judge_rows = [json.loads(l) for l in Path(args.judge).read_text().splitlines() if l.strip()]
    valid = [r for r in judge_rows if r["verdict"] == "vulnerable"]
    print(f"Vulnerable samples: {len(valid)}")

    dataset_rows = {
        json.loads(l)["pilot_id"]: json.loads(l)
        for l in Path(args.dataset).read_text().splitlines() if l.strip()
    }

    written = skipped = 0

    for idx, jrow in enumerate(valid):
        pid       = jrow["pilot_id"]
        meta      = dataset_rows.get(pid, {})
        d         = samples_dir / pid
        func_name = jrow.get("func_name") or meta.get("func_name") or meta.get("function", "")
        lang      = meta.get("lang") or "c"
        file_name = "solution.cc" if lang == "cpp" else "solution.c"

        starter_path = d / "starter.cc"
        if not starter_path.exists():
            print(f"  [skip] {pid} — no starter.cc")
            skipped += 1
            continue

        atk_path = find_best_output(pid, rounds_dir, only_rounds)
        if atk_path is None:
            print(f"  [skip] {pid} — no attacker output in {only_rounds}")
            skipped += 1
            continue

        starter_src  = starter_path.read_text(errors="replace")
        attacker_raw = atk_path.read_text(errors="replace")
        attacker_npd_line = extract_attacker_npd_line(attacker_raw)
        attacker_clean    = strip_npd_marker(attacker_raw)

        # Splice attacker's body into starter.cc to get the full file
        body = extract_body(func_name, attacker_clean)
        if body is None:
            print(f"  [skip] {pid} — extract_body failed for {func_name!r}")
            skipped += 1
            continue

        spliced = splice_body(func_name, starter_src, body)
        if spliced is None:
            print(f"  [skip] {pid} — splice_body failed for {func_name!r}")
            skipped += 1
            continue

        # Split spliced file into context (before func) and target_function
        context_part, target_part = split_file(spliced, func_name)

        # Prepend raw_auxiliary.cc to context if present
        aux_path = d / "raw_auxiliary.cc"
        if aux_path.exists():
            aux = aux_path.read_text(errors="replace").strip()
            if aux:
                context_part = f"// auxiliary context\n{aux}\n\n// same-file context\n{context_part}"

        code = f"// context\n{context_part}\n\n// target function\n{target_part}"

        entry = {
            "code":               code,
            "context":            context_part,
            "target_function":    target_part,
            "function_name":      func_name,
            "deref_line":         attacker_npd_line,
            "caller":             func_name,
            "file_name":          file_name,
            "CWE_ID":             ["CWE-476"],
            "RELATED_CWE":        [],
            "stack_trace":        "",
            "target":             1,
            "language":           lang,
            "dataset":            args.dataset_tag,
            "idx":                idx,
            "slug":               pid,
            "variant":            "CLEAN",
            # judge metadata (ignored by detectors, useful for analysis)
            "same_implementation": jrow.get("same_implementation"),
            "same_npd_site":       jrow.get("same_npd_site"),
            "npd_site_match":      npd_site_match(
                                       attacker_npd_line,
                                       jrow.get("generated_npd_line", ""),
                                   ),
        }

        out_dir = out_root / "baseline" / f"repository_{pid}"
        out_dir.mkdir(parents=True, exist_ok=True)

        (out_dir / f"{pid}_CLEAN.json").write_text(json.dumps([entry], indent=2))
        (out_dir / "solution.cc").write_text(attacker_clean.strip() + "\n")

        written += 1
        print(f"  {pid}  ({func_name})  deref_line={attacker_npd_line[:60]!r}")

    print(f"\nDone — {written} written, {skipped} skipped → {out_root}/baseline/")


if __name__ == "__main__":
    main()
