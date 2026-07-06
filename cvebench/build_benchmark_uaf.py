#!/usr/bin/env python3
"""
build_benchmark_uaf.py — Stage 3: build the CVE UAF benchmark from judge
output (judge_cve_new_uaf.py), mirroring build_benchmark.py's NPD approach.

Only samples with judge verdict=="vulnerable" are included — this drops
"broken" (malformed/off-purpose generations) and any "not_vulnerable"
automatically, matching NPD's gate (compile+test pass AND independent
blind-judge confirmation, not compile+test alone).

same_implementation / same_uaf_site come directly from the judge (vs. the
ORIGINAL historical CVE — expected to be low given UAF's 5-mechanism design
space and no per-sample hints; see project notes). uaf_site_match is
computed here (mirrors build_benchmark.py's npd_site_match) between the
attacker's own marked line and the judge's independently-found line — the
self-consistency check, not a history-match check.

Layout differs from NPD too: this pipeline ran generate_attacker.py and
patch_and_test.py directly into samples_cve_uaf/<pid>/ (no rounds/r1,r2
split — single round), so there is no find_best_output/rounds logic here.

Usage:
  python3 cvebench/build_benchmark_uaf.py \\
      --judge   cvebench/judge_uaf.jsonl \\
      --dataset cvebench/f3_uaf_ids.jsonl \\
      --samples cvebench/samples_cve_uaf \\
      --out-root benchmark/cvebench_full_uaf
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from cvebench.patch_and_test import extract_body, splice_body
from cvebench.build_benchmark import split_file  # CWE-agnostic, reused verbatim

REPO_ROOT = Path(__file__).parent.parent

UAF_MARKER = "/* UAF site */"


def strip_uaf_marker(code: str) -> str:
    return "\n".join(l for l in code.splitlines() if UAF_MARKER not in l)


def uaf_site_match(a: str, g: str) -> bool:
    """Attacker's own claimed site vs judge's independently-found site
    (self-consistency check — not a match against the original historical CVE)."""
    a, g = (a or "").strip(), (g or "").strip()
    if not a or a == "none" or not g or g in ("none", "null"):
        return False
    return a == g or a in g or g in a


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--judge",    required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--samples", required=True)
    ap.add_argument("--out-root", required=True)
    args = ap.parse_args()

    samples_dir = Path(args.samples)
    out_root    = REPO_ROOT / args.out_root

    judge_rows = [json.loads(l) for l in Path(args.judge).read_text().splitlines() if l.strip()]
    valid = [r for r in judge_rows if r["verdict"] == "vulnerable"]
    print(f"Judge-confirmed vulnerable: {len(valid)} / {len(judge_rows)}")

    dataset_rows = {
        json.loads(l)["pilot_id"]: json.loads(l)
        for l in Path(args.dataset).read_text().splitlines() if l.strip()
    }

    written = skipped = 0

    for jrow in valid:
        pid       = jrow["pilot_id"]
        meta      = dataset_rows.get(pid, {})
        d         = samples_dir / pid
        func_name = jrow.get("func_name") or meta.get("func_name") or meta.get("function", "")
        lang      = meta.get("lang") or "c"
        file_name = "solution.cc" if lang == "cpp" else "solution.c"

        starter_path = d / "starter.cc"
        atk_path     = d / "attacker_output.cc"
        if not starter_path.exists() or not atk_path.exists():
            print(f"  [skip] {pid} — missing starter.cc or attacker_output.cc")
            skipped += 1
            continue

        starter_src  = starter_path.read_text(errors="replace")
        attacker_raw = atk_path.read_text(errors="replace")
        attacker_clean = strip_uaf_marker(attacker_raw)

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

        before_part, target_part, after_part = split_file(spliced, func_name)

        aux_path = d / "raw_auxiliary.cc"
        auxiliary_file = aux_path.read_text(errors="replace").strip() if aux_path.exists() else ""

        task_path = d / "task.md"
        task_description = task_path.read_text(errors="replace").strip() if task_path.exists() else ""

        result_path = d / "attacker_result.json"
        patch_verdict = None
        if result_path.exists():
            patch_verdict = json.loads(result_path.read_text()).get("verdict")

        entry = {
            "primary_file":       spliced,
            "attacker_output":    attacker_clean,
            "auxiliary_file":     auxiliary_file,
            "task_description":   task_description,
            "context_before":     before_part,
            "target_function":    target_part,
            "context_after":      after_part,
            "function_name":      func_name,
            "file_name":          file_name,
            "CWE_ID":             ["CWE-416"],
            "language":           lang,
            "slug":               pid,
            "variant":            "CLEAN",
            "cve_id":             meta.get("cve_id", ""),
            "repo_url":           meta.get("repo_url", ""),
            "patch_and_test_verdict": patch_verdict,
            # judge metadata (ignored by detectors, useful for analysis)
            "same_implementation": jrow.get("same_implementation"),
            "same_uaf_site":       jrow.get("same_uaf_site"),
            "uaf_site_match":      uaf_site_match(
                                       jrow.get("attacker_uaf_line", ""),
                                       jrow.get("generated_uaf_line", ""),
                                   ),
            "attacker_uaf_line":   jrow.get("attacker_uaf_line") or "none",
            "generated_uaf_line":  jrow.get("generated_uaf_line"),
        }

        out_dir = out_root / "baseline" / f"repository_{pid}"
        out_dir.mkdir(parents=True, exist_ok=True)

        (out_dir / f"{pid}_CLEAN.json").write_text(json.dumps([entry], indent=2))
        (out_dir / "solution.cc").write_text(attacker_clean.strip() + "\n")

        written += 1
        print(f"  {pid}  ({func_name})")

    print(f"\nDone — {written} written, {skipped} skipped → {out_root}/baseline/")


if __name__ == "__main__":
    main()
