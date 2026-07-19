#!/usr/bin/env python3
"""
build_benchmark.py — Stage 3: build the final CVE NPD benchmark from judge output.

Takes the 128 verified vulnerable samples from judge_r1r2.jsonl, splices
the attacker's function body into starter.cc, splits into context + target_function,
and writes to benchmark/cvebench_full/baseline/repository_<pid>/<pid>_CLEAN.json
in the schema used by VulnLLM-R, OpenVul, and the adaptive attacker.

Usage:
  python3 cvebench/build_benchmark.py \\
      --judge   cvebench/judge_r1r2.jsonl \\
      --dataset cvebench/f3_nolimit_dedup_func.slim.jsonl \\
      --samples cvebench/samples_cve_fix \\
      --rounds  cvebench/rounds \\
      --out-root benchmark/cvebench_full \\
      [--only-rounds r1 r2] [--dataset-tag cvebench_full]
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from cvebench.patch_and_test import extract_body, splice_body

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


def npd_site_match(a: str, g: str) -> bool:
    a, g = (a or "").strip(), (g or "").strip()
    if not a or a == "none" or not g or g in ("none", "null"):
        return False
    return a == g or a in g or g in a


def _is_definition_at(code: str, paren_open: int) -> bool:
    """
    Given the index of the '(' that opens a candidate function's parameter
    list, determine whether this occurrence is a definition (parameter list
    followed by '{', modulo whitespace/comments) rather than a bare
    declaration/prototype (parameter list followed by ';').
    """
    depth = 1
    i = paren_open + 1
    n = len(code)
    in_string = in_char = False
    while i < n and depth > 0:
        c = code[i]
        if in_string:
            if c == '\\':
                i += 1
            elif c == '"':
                in_string = False
        elif in_char:
            if c == '\\':
                i += 1
            elif c == "'":
                in_char = False
        elif c == '"':
            in_string = True
        elif c == "'":
            in_char = True
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        i += 1
    if depth != 0:
        return False

    # Skip whitespace/comments after the closing ')' to find the first
    # significant character (also tolerates trailing qualifiers like
    # 'const'/'noexcept' and C++ initializer lists starting with ':').
    while i < n:
        c = code[i]
        if c.isspace():
            i += 1
        elif c == '/' and i + 1 < n and code[i + 1] == '/':
            nl = code.find('\n', i)
            i = n if nl == -1 else nl + 1
        elif c == '/' and i + 1 < n and code[i + 1] == '*':
            end = code.find('*/', i + 2)
            i = n if end == -1 else end + 2
        elif code[i:i + 5] == 'const' and not code[i + 5:i + 6].isalnum():
            i += 5
        elif code[i:i + 8] == 'noexcept' and not code[i + 8:i + 9].isalnum():
            i += 8
        elif c == ':':
            # C++ constructor initializer list — still a definition.
            return True
        elif c == '#':
            # Preprocessor line (e.g. #else/#endif splitting an #ifdef'd
            # signature from its body) — skip to end of line.
            nl = code.find('\n', i)
            i = n if nl == -1 else nl + 1
        else:
            break
    return i < n and code[i] == '{'


def split_file(code: str, func_name: str) -> tuple[str, str, str]:
    """
    Split code into (before, target_function, after) where target_function is
    just that function.

    Candidates for func_name+'(' are tried in file order; the first one that
    is actually a definition (parameter list followed by '{', not ';') wins.
    Without this check, a function with a forward declaration earlier in the
    file would match the declaration, and the brace-walk below would then
    silently attach to whatever unrelated function's body happens to be the
    next '{...}' block in the file.
    """
    pattern = re.compile(
        r'^\s*'
        r'(?:(?:static|inline|explicit|virtual|override|extern)\s+)*'
        r'(?:\w[\w\s:*&<>()]*?[\s*])?'
        r'(?:\w[\w:]*::)*'
        + re.escape(func_name) + r'\s*\(',
        re.MULTILINE,
    )
    m = None
    first_match = None
    for cand in pattern.finditer(code):
        if first_match is None:
            first_match = cand
        # cand.end() - 1 is the index of the '(' just consumed by the regex.
        if _is_definition_at(code, cand.end() - 1):
            m = cand
            break
    if m is None:
        m = first_match  # fall back to old (possibly-declaration) behavior
    if not m:
        return code.rstrip(), "", ""

    func_start = m.start()
    rest = code[func_start:]

    # Walk rest char-by-char tracking brace depth to find end of function
    depth = 0
    i = 0
    in_line_comment = in_block_comment = in_string = in_char = False
    while i < len(rest):
        c = rest[i]
        if in_line_comment:
            if c == '\n':
                in_line_comment = False
        elif in_block_comment:
            if c == '*' and i + 1 < len(rest) and rest[i + 1] == '/':
                in_block_comment = False
                i += 1
        elif in_string:
            if c == '\\':
                i += 1
            elif c == '"':
                in_string = False
        elif in_char:
            if c == '\\':
                i += 1
            elif c == "'":
                in_char = False
        else:
            if c == '/' and i + 1 < len(rest):
                if rest[i + 1] == '/':
                    in_line_comment = True; i += 1
                elif rest[i + 1] == '*':
                    in_block_comment = True; i += 1
            elif c == '"':
                in_string = True
            elif c == "'":
                in_char = True
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return (
                        code[:func_start].rstrip(),
                        rest[:i + 1],
                        rest[i + 1:].strip(),
                    )
        i += 1

    return code[:func_start].rstrip(), rest, ""  # fallback: no closing brace found


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

    for jrow in valid:
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

        # Split spliced file into before / function / after
        before_part, target_part, after_part = split_file(spliced, func_name)

        # Load auxiliary file separately (cross-file helpers)
        aux_path = d / "raw_auxiliary.cc"
        auxiliary_file = ""
        if aux_path.exists():
            auxiliary_file = aux_path.read_text(errors="replace").strip()

        # Load task description
        task_path = d / "task.md"
        task_description = task_path.read_text(errors="replace").strip() if task_path.exists() else ""

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
            "CWE_ID":             ["CWE-476"],
            "language":           lang,
            "slug":               pid,
            "variant":            "CLEAN",
            # provenance (links back to MegaVul / original CVE)
            "cve_id":             meta.get("cve_id", ""),
            "repo_url":           meta.get("repo_url", ""),
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
        print(f"  {pid}  ({func_name})")

    print(f"\nDone — {written} written, {skipped} skipped → {out_root}/baseline/")


if __name__ == "__main__":
    main()
