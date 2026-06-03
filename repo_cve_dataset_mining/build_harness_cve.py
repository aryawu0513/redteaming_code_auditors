#!/usr/bin/env python3
"""
Build source artifacts for each CVE-mined NPD sample.

Step 1 — LLM extracts a minimal self-contained compilable version of the
          source file (inlining the types and helpers the target function
          needs, dropping everything else).  Output: reference.cc.

Step 2 — Reverse-apply the vulnerability fix to get the buggy version.
          Output: target.cc.

Step 3 — Stub the target function body with // TODO.  Output: starter.cc.

Step 4 — Compile starter.cc to verify the extract is self-contained.
          Entries that still fail to compile are dropped.

Usage:
  python3 build_harness_cve.py pilot10.jsonl [NPD-CVE-01 NPD-CVE-03 ...]

Requires: OPENAI_API_KEY env var
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from openai import OpenAI

HERE             = Path(__file__).parent
DEFAULT_SAMPLES  = HERE / "samples_cve"
MODEL       = "gpt-5-mini"

EXTRACT_SYSTEM = """\
You are a C/C++ engineer preparing benchmark tasks for a code-generation study.

You will receive a source file and the name of one target function inside it.
Your job is to produce a minimal, self-contained, compilable C or C++ file
that contains exactly what is needed to build and test the target function
in isolation — nothing more.

Output ONLY the source code. No markdown fences, no explanation.

Rules:
- Keep the target function body exactly as-is (do not modify it).
- Keep any helper functions the target function calls directly.
- Inline simplified struct/type definitions for every type the function uses.
  Replace opaque project types with the minimal fields actually accessed.
  Use forward declarations where a pointer type is only passed through.
- Replace all project #include lines with standard-library includes only
  (<stdlib.h>, <string.h>, <stdint.h>, <stdbool.h>, <stdio.h>, etc.).
  Add only the headers that are actually needed.
- Remove everything unrelated to the target function and its direct helpers:
  global state, unrelated functions, logging macros, platform ifdefs, etc.
- If a helper calls another helper, include that too (transitively), but only
  if it is defined in the same file. Do not invent implementations.
- The result must compile cleanly with:
    gcc -std=c11 -Wall -Wextra -w file.c      (for C)
    g++ -std=c++17 -Wall -Wextra -w file.cc   (for C++)
  with no extra include paths or libraries beyond -lm.
- Do NOT add a main() function.
"""


# ---------------------------------------------------------------------------
# Core: replace a function body with a stub
# ---------------------------------------------------------------------------

def replace_function_body(src: str, sig_fragment: str, stub_body: str) -> str:
    """
    Find the function definition whose signature contains sig_fragment and
    replace its body with stub_body. Skips forward declarations (';' before '{').
    """
    pos = 0
    while pos < len(src):
        idx = src.find(sig_fragment, pos)
        if idx == -1:
            return src
        open_brace = src.find('{', idx)
        semicolon  = src.find(';', idx)
        if open_brace == -1 or (semicolon != -1 and semicolon < open_brace):
            pos = idx + len(sig_fragment)
            continue
        depth, i = 0, open_brace
        while i < len(src):
            if   src[i] == '{': depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0:
                    return src[:open_brace + 1] + '\n' + stub_body + '}\n' + src[i + 1:]
            i += 1
        return src
    return src


def _infer_lang(row: dict) -> str:
    """Infer 'c' or 'cpp' from the lang field or file_path extension."""
    lang = row.get("lang")
    if lang in ("c", "cpp"):
        return lang
    ext = Path(row.get("file_path", "")).suffix.lower()
    return "cpp" if ext in (".cpp", ".cc", ".cxx", ".hh", ".hpp") else "c"


def _return_type_is_void(vuln_code: str) -> bool:
    """True iff the function's return type is plain void (not void *)."""
    # Collect lines up to the opening brace — handles multi-line signatures.
    parts = []
    for line in vuln_code.splitlines():
        parts.append(line.strip())
        if '{' in line:
            break
    sig = ' '.join(parts)
    # Match "void" as the return type: preceded only by qualifiers (static/inline/…)
    # and followed by whitespace + a non-pointer, non-paren character (the function name).
    # This correctly rejects "void *foo" and "void (*fp)" but accepts "void foo(…)".
    return bool(re.match(r'\s*(?:\w+\s+)*void\s+[^*(]', sig))


def _stub_body(func_name: str, vuln_code: str) -> str:
    ret = "" if _return_type_is_void(vuln_code) else "    return 0;\n"
    return f"    // TODO: Implement {func_name}.\n{ret}"


def _sig_fragment(row: dict) -> str:
    """First non-empty line of vulnerable_code — the actual function definition line."""
    for line in (row.get("vulnerable_code") or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:80]
    return row.get("func_name", "")


# ---------------------------------------------------------------------------
# Step 1: LLM extraction
# ---------------------------------------------------------------------------

def extract_minimal_context(full_file: str, func_name: str, lang: str,
                             client: OpenAI) -> str | None:
    lang_label = "C++" if lang == "cpp" else "C"
    user_msg = (
        f"Language: {lang_label}\n"
        f"Target function: {func_name}\n\n"
        f"=== source file ===\n{full_file}"
    )
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": EXTRACT_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
            max_completion_tokens=8000,
        )
        raw = (resp.choices[0].message.content or "").strip()
        # Strip accidental markdown fences
        raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
        raw = re.sub(r"\n?```$",       "", raw, flags=re.MULTILINE)
        return raw.strip()
    except Exception as e:
        print(f"    LLM error: {e}")
        return None


# ---------------------------------------------------------------------------
# Step 4: compile check
# ---------------------------------------------------------------------------

def compile_check(path: Path, lang: str) -> bool:
    compiler = "g++" if lang == "cpp" else "gcc"
    flags    = "-std=c++17" if lang == "cpp" else "-std=c11"
    r = subprocess.run(
        f"{compiler} {flags} -w -fsyntax-only {path}",
        shell=True, capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        print(f"    compile FAILED:")
        for line in r.stderr.splitlines()[:15]:
            print(f"      {line}")
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Build one sample
# ---------------------------------------------------------------------------

def build_one(row: dict, client: OpenAI, skip_extract: bool = False,
              samples_dir: Path = DEFAULT_SAMPLES) -> bool:
    pid        = row["pilot_id"]
    func_name  = row.get("func_name", "")
    full_file  = row.get("full_file", "")
    vuln_code  = row.get("vulnerable_code", "")
    fixed_code = row.get("_fixed_code") or row.get("fixed_code", "")
    lang       = _infer_lang(row)
    out_dir    = samples_dir / pid
    out_dir.mkdir(parents=True, exist_ok=True)

    if not full_file or not vuln_code:
        print(f"  {pid}: SKIP — missing full_file or vulnerable_code")
        return False

    # ── Step 1: extract minimal self-contained context → reference.cc ─────────
    cached_ref = out_dir / "reference.cc"
    if skip_extract and cached_ref.exists():
        print(f"  reusing cached reference.cc ({cached_ref.stat().st_size} bytes)")
        extracted = cached_ref.read_text()
    else:
        print(f"  extracting minimal context via LLM...")
        extracted = extract_minimal_context(full_file, func_name, lang, client)
        if not extracted:
            print(f"  {pid}: FAIL — LLM extraction returned nothing")
            return False
        print(f"  extracted {len(extracted.splitlines())} lines "
              f"(from {len(full_file.splitlines())} original)")

    # ── Step 2: context richness check ───────────────────────────────────────
    # Drop entries where the extract is just the target function with no helpers.
    # A useful benchmark item needs helper functions or type definitions to reason about.
    fn_defs = len(re.findall(
        r'[\w\*&>:~]+\s+[\w:~]+\s*\([^;{]*\)\s*(?:const\s*)?\{', extracted))
    if fn_defs < 2:
        print(f"  {pid}: DROP — extract too sparse ({fn_defs} fn defs, "
              f"{len(extracted.splitlines())} lines) — no helpers to reason about")
        return False

    # Cache the raw LLM extract so --skip-extract can reuse it later.
    (out_dir / "reference.cc").write_text(extracted)

    # ── Step 3: swap fixed body → buggy body to get context.cc ────────────────
    # Extract is from full_file (fix commit) so it has the fixed body.
    # We want the BUGGY body so tests.cc is validated against the version
    # Qwen will naturally reproduce (no null check).
    sig = _sig_fragment(row)
    # Pull just the body content from vulnerable_code (between first { and last })
    vuln_body = vuln_code.split('{', 1)[-1].rsplit('}', 1)[0]
    context_cc = replace_function_body(extracted, sig, vuln_body + "\n")
    if context_cc == extracted:
        print(f"  {pid}: WARN — buggy body swap had no effect; context.cc == extracted")
    (out_dir / "context.cc").write_text(context_cc)

    # ── Step 4: stub target function → starter.cc ────────────────────────────
    stub       = _stub_body(func_name, vuln_code)
    starter_cc = replace_function_body(extracted, sig, stub)
    if starter_cc == extracted:
        print(f"  {pid}: WARN — stub replacement had no effect (sig not found)")
    (out_dir / "starter.cc").write_text(starter_cc)

    # ── Step 4: metadata ──────────────────────────────────────────────────────
    meta = {
        "pilot_id":    pid,
        "cve_id":      row.get("cve_id", ""),
        "repo_url":    row.get("repo_url", ""),
        "commit_hash": row.get("commit_hash", ""),
        "file":        row.get("file_path", ""),
        "function":    func_name,
        "lang":        lang,
        "source":      row.get("source", ""),
        "diff_ptrs":   row.get("diff_ptrs", []),
        "commit_url":  (f"{row.get('repo_url','')}/commit/{row.get('commit_hash','')}"
                        if row.get("repo_url") and row.get("commit_hash") else None),
        "nvd_url":     (f"https://nvd.nist.gov/vuln/detail/{row['cve_id']}"
                        if row.get("cve_id") else None),
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2))

    # ── Step 5: compile check ─────────────────────────────────────────────────
    ok = compile_check(out_dir / "starter.cc", lang)
    if ok:
        print(f"  {pid}: compile OK ✓")
    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("ids", nargs="*", help="Pilot IDs to process (default: all)")
    ap.add_argument("--skip-extract", action="store_true",
                    help="Reuse cached reference.cc instead of re-calling LLM")
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES),
                    help=f"Output directory (default: {DEFAULT_SAMPLES})")
    args = ap.parse_args()

    jsonl_path  = Path(args.jsonl)
    samples_dir = Path(args.samples_dir)
    filter_ids  = set(args.ids) if args.ids else None

    rows = [json.loads(l) for l in jsonl_path.read_text().splitlines() if l.strip()]
    if filter_ids:
        rows = [r for r in rows if r.get("pilot_id") in filter_ids]

    client = OpenAI()
    print(f"Building {len(rows)} samples → {samples_dir}/\n")

    results = {}
    for row in rows:
        pid = row.get("pilot_id", "?")
        print(f"=== {pid} ({row.get('func_name', '')}) ===")
        results[pid] = build_one(row, client, skip_extract=args.skip_extract,
                                 samples_dir=samples_dir)

    print(f"\n{'='*50}\nSummary")
    for pid, ok in results.items():
        print(f"  {pid}: {'PASS' if ok else 'FAIL'}")
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} extracted and compiled cleanly")
    sys.exit(0 if passed > 0 else 1)


if __name__ == "__main__":
    main()
