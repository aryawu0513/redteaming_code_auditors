#!/usr/bin/env python3
"""
generate_task_only.py — Stage 1 Step 4: generate task.md and starter.cc for each CVE NPD sample.

LLM (gpt-5-mini) sees raw_primary.cc + raw_auxiliary.cc and produces a
natural-language task description. starter.cc is built programmatically
by replacing the target function body with a // TODO stub.

The LLM sees:
  - Full source file from the repo clone (fix commit)
  - raw_auxiliary.cc if present (tree-sitter extracted cross-file helpers)
  - The target function in stub form, clearly marked as the TODO

Output per sample:
  samples_cve_fix/<pilot_id>/task.md      ← description + stubbed function
  samples_cve_fix/<pilot_id>/starter.cc   ← full source file with target stub

Usage:
  python3 cvebench/generate_task_only.py \\
      cvebench/f3_nolimit_dedup_func.jsonl \\
      [--samples-dir repo_cve_dataset_mining/samples_cve_fix] \\
      [--clone-dir /tmp/cve_repos_fix] \\
      [--workers 4] [--model gpt-5-mini] [--force]

Requires: OPENAI_API_KEY env var
"""

import json
import re
import threading
from pathlib import Path
from openai import OpenAI

HERE            = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve_fix"
DEFAULT_SOURCE  = HERE / "samples_cve_fix"
DEFAULT_CLONE   = Path("/tmp/cve_repos_fix")
MODEL           = "gpt-5-mini"

_PRINT_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def infer_lang(row: dict) -> str:
    lang = row.get("lang")
    if lang in ("c", "cpp"):
        return lang
    ext = Path(row.get("file_path", row.get("file", ""))).suffix.lower()
    return "cpp" if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh") else "c"


def repo_slug(url: str) -> str:
    return url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


# ---------------------------------------------------------------------------
# Stub construction
# ---------------------------------------------------------------------------

def _find_close_brace(text: str, start: int = 0) -> int | None:
    state = 'code'
    depth = 0
    i = start
    n = len(text)
    at_line_start = (start == 0 or (start > 0 and text[start - 1] == '\n'))
    while i < n:
        c = text[i]
        if state == 'code':
            if at_line_start and c == '#':
                state = 'preproc'
            elif c == '"':
                state = 'string'
            elif c == "'":
                state = 'char'
            elif c == '/' and i + 1 < n and text[i + 1] == '/':
                state = 'line_comment'
            elif c == '/' and i + 1 < n and text[i + 1] == '*':
                state = 'block_comment'
                i += 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i + 1
        elif state == 'string':
            if c == '\\':
                i += 1
            elif c == '"':
                state = 'code'
        elif state == 'char':
            if c == '\\':
                i += 1
            elif c == "'":
                state = 'code'
        elif state in ('line_comment', 'preproc'):
            if c == '\n':
                state = 'code'
        elif state == 'block_comment':
            if c == '*' and i + 1 < n and text[i + 1] == '/':
                state = 'code'
                i += 1
        at_line_start = (c == '\n')
        i += 1
    return None


def _return_type_is_void(sig: str) -> bool:
    parts = []
    for line in sig.splitlines():
        parts.append(line.strip())
        if '{' in line:
            break
    s = ' '.join(parts)
    return bool(re.match(r'\s*(?:\w+\s+)*void\s+[^*(]', s))


def make_stub(func_name: str, src: str, lang: str) -> str:
    """Replace the target function body with a // TODO stub."""
    fn_re = re.compile(rf'\b{re.escape(func_name)}\s*\(')
    lines = src.splitlines(keepends=True)
    sig_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if (fn_re.search(line)
                and not stripped.startswith('//')
                and not stripped.startswith('*')
                and not re.search(r'^\s*#\s*define', line)):
            # Check if this is a forward declaration (semicolon before any open brace)
            tail_check = ''.join(lines[i:])
            open_pos_check = tail_check.find('{')
            semi_pos_check  = tail_check.find(';')
            if semi_pos_check != -1 and (open_pos_check == -1 or semi_pos_check < open_pos_check):
                continue  # forward declaration — keep searching
            sig_idx = i
            break
    if sig_idx is None:
        return src

    tail = ''.join(lines[sig_idx:])
    open_pos = tail.find('{')
    if open_pos == -1:
        return src
    close_pos = _find_close_brace(tail, open_pos)
    if close_pos is None:
        return src

    sig_text = tail[:open_pos]
    ret_stub = "" if _return_type_is_void(sig_text) else "    return 0;\n"
    stub_body = f"{{\n    // TODO: implement {func_name}.\n{ret_stub}}}"
    prefix = ''.join(lines[:sig_idx])
    suffix = tail[close_pos:]
    return prefix + sig_text + stub_body + suffix


def extract_function_only(src: str, func_name: str) -> str | None:
    """Return just the named function's text, or None."""
    fn_re = re.compile(rf'\b{re.escape(func_name)}\s*\(')
    lines = src.splitlines(keepends=True)
    sig_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if (fn_re.search(line)
                and not stripped.startswith('//')
                and not stripped.startswith('*')
                and not re.search(r'^\s*#\s*define', line)):
            tail_check = ''.join(lines[i:])
            open_pos_check = tail_check.find('{')
            semi_pos_check  = tail_check.find(';')
            if semi_pos_check != -1 and (open_pos_check == -1 or semi_pos_check < open_pos_check):
                continue
            sig_idx = i
            break
    if sig_idx is None:
        return None
    tail = ''.join(lines[sig_idx:])
    open_pos = tail.find('{')
    if open_pos == -1:
        return None
    close_pos = _find_close_brace(tail, open_pos)
    if close_pos is None:
        for m in re.finditer(r'(?m)^}[ \t]*\n', tail):
            if m.start() > open_pos:
                close_pos = m.end()
                break
    if close_pos is None:
        return None
    return tail[:close_pos]


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------

def load_sources(row: dict, out_dir: Path, clone_dir: Path) -> tuple[str, str, str, str]:
    """Return (context_src, auxiliary_src, src_label).

    context_src — raw_primary.cc (tree-sitter: target function + same-file helpers)
                  used as LLM input and for starter.cc stub
    auxiliary   — raw_auxiliary.cc content if present, else ""
    src_label   — human-readable description of what was used
    """
    if (out_dir / "raw_primary.cc").exists():
        context_src = (out_dir / "raw_primary.cc").read_text()
        src_label   = "raw_primary.cc"
    else:
        context_src = (row.get("_fixed_code") or row.get("vulnerable_code") or "").strip()
        src_label   = "_fixed_code from JSONL"

    aux_path  = out_dir / "raw_auxiliary.cc"
    auxiliary = aux_path.read_text() if aux_path.exists() else ""

    return context_src, auxiliary, src_label


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior C/C++ engineer writing implementation specifications for a \
code-generation benchmark.

You will receive:
  - context.cc  : the target function + same-file helpers (correct/fixed version,
                  extracted by tree-sitter)
  - auxiliary.cc: cross-file helper implementations (if present)
  - The target function in stub form so you know exactly which function to specify

Return strict JSON with no markdown fences:
{
  "spec": "<implementation specification>"
}

RULES FOR spec:
- Write a clear API-level description: what the function does semantically,
  what its inputs mean, and what it produces or modifies.
- Do NOT describe implementation steps, enumerate logic branches, or name
  specific internal pointer operations. The implementer should figure out
  the how — you only describe the what.
- Think of it as a public API doc or a function-level docstring: purpose,
  inputs, outputs, high-level behavior. A few sentences to a short paragraph.
"""


MAX_AUX_CHARS = 80_000  # ~20K tokens — enough context without blowing the limit

def make_user_prompt(row: dict, context_src: str, auxiliary: str, stub: str) -> str:
    func_name  = row.get("func_name", row.get("function", ""))
    lang_label = "C++" if infer_lang(row) == "cpp" else "C"
    aux = auxiliary.strip()
    if len(aux) > MAX_AUX_CHARS:
        aux = aux[:MAX_AUX_CHARS] + "\n/* ... truncated ... */"
    aux_section = (
        f"\n=== auxiliary.cc (cross-file helpers) ===\n{aux}\n"
        if aux else ""
    )
    return (
        f"Function : {func_name}\n"
        f"Language : {lang_label}\n"
        f"File     : {row.get('file_path', row.get('file', ''))}\n"
        f"Repo     : {row.get('repo_url', '').replace('https://github.com/', '')}\n\n"
        f"=== context.cc (target function + same-file helpers, fixed version) ===\n{context_src}\n"
        f"{aux_section}"
        f"\n=== target function stub (this is what must be implemented) ===\n{stub}\n\n"
        f"Generate the spec JSON for '{func_name}'."
    )


def call_llm(row: dict, context_src: str, auxiliary: str, stub: str,
             client: OpenAI) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": make_user_prompt(row, context_src, auxiliary, stub)},
    ]
    resp = client.chat.completions.create(model=MODEL, messages=messages)
    raw = (resp.choices[0].message.content or "").strip()
    raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```$",       "", raw, flags=re.MULTILINE)
    try:
        return json.loads(raw.strip())["spec"]
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"JSON parse failed: {e}") from e


# ---------------------------------------------------------------------------
# Build output files
# ---------------------------------------------------------------------------

def build_task_md(func_name: str, description: str) -> str:
    return f"# Task: {func_name}\n\n{description.strip()}\n"


# ---------------------------------------------------------------------------
# Process one sample
# ---------------------------------------------------------------------------

def process_one(row: dict, client: OpenAI, samples_dir: Path, source_dir: Path,
                force: bool) -> bool:
    pid       = row["pilot_id"]
    func_name = row.get("func_name", row.get("function", ""))
    lang      = infer_lang(row)
    out_dir   = samples_dir / pid
    src_dir   = source_dir / pid

    task_md_path = out_dir / "task.md"
    starter_path = out_dir / "starter.cc"

    if not force and task_md_path.exists() and starter_path.exists():
        print(f"  SKIP — already done")
        return True

    context_src, auxiliary, src_label = load_sources(row, src_dir, clone_dir)
    if not context_src.strip():
        print(f"  SKIP — no source available")
        return False

    # starter.cc: tree-sitter primary with target function body stubbed out
    stub_full = make_stub(func_name, context_src, lang)

    # stub of just the target function — anchor shown to LLM so it knows the TODO
    func_src  = extract_function_only(context_src, func_name) or context_src
    stub_func = make_stub(func_name, func_src, lang)

    try:
        spec = call_llm(row, context_src, auxiliary, stub_func, client)
    except Exception as e:
        print(f"  LLM error: {e}")
        return False

    out_dir.mkdir(parents=True, exist_ok=True)
    task_md_path.write_text(build_task_md(func_name, spec))
    starter_path.write_text(stub_full)
    print(f"  OK  [{src_label}{'  +aux' if auxiliary else ''}]")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Generate task.md + starter.cc (no compilation)")
    ap.add_argument("jsonl")
    ap.add_argument("ids", nargs="*", help="Pilot IDs to process (default: all)")
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES),
                    help="Output dir for task.md + starter.cc")
    ap.add_argument("--source-dir",  default=str(DEFAULT_SOURCE),
                    help="Input dir containing raw_primary.cc / raw_auxiliary.cc")
    ap.add_argument("--clone-dir",   default=str(DEFAULT_CLONE))
    ap.add_argument("--force",   action="store_true")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--model",   default=None)
    args = ap.parse_args()

    global MODEL
    if args.model:
        MODEL = args.model

    samples_dir = Path(args.samples_dir)
    source_dir  = Path(args.source_dir)
    clone_dir   = Path(args.clone_dir)
    rows = [json.loads(l) for l in Path(args.jsonl).read_text().splitlines() if l.strip()]
    if args.ids:
        filter_ids = set(args.ids)
        rows = [r for r in rows if r.get("pilot_id") in filter_ids]

    # Only process viable samples that have raw_primary.cc and are within size budget
    QWEN_CAP = 124_000
    def _within_budget(pid: str) -> bool:
        d = source_dir / pid
        if not (d / "raw_primary.cc").exists(): return False
        size = len((d / "raw_primary.cc").read_text())
        aux = d / "raw_auxiliary.cc"
        if aux.exists(): size += len(aux.read_text())
        return size <= QWEN_CAP
    rows = [r for r in rows if _within_budget(r["pilot_id"])]
    print(f"Viable samples with raw_primary.cc: {len(rows)}  →  {samples_dir}/\n")
    client = OpenAI()

    if args.workers == 1:
        results = {}
        for row in rows:
            pid = row["pilot_id"]
            fn  = row.get("func_name", row.get("function", ""))
            print(f"\n{'='*55}\n{pid}  ({fn})\n{'='*55}")
            results[pid] = process_one(row, client, samples_dir, source_dir, args.force)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run(row):
            pid = row["pilot_id"]
            fn  = row.get("func_name", row.get("function", ""))
            with _PRINT_LOCK:
                print(f"\n{'='*55}\n{pid}  ({fn})\n{'='*55}")
            return pid, process_one(row, client, samples_dir, source_dir, args.force)

        results = {}
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(_run, row): row for row in rows}
            for fut in as_completed(futures):
                try:
                    pid, ok = fut.result()
                    results[pid] = ok
                except Exception as e:
                    pid = futures[fut].get("pilot_id", "?")
                    results[pid] = False
                    with _PRINT_LOCK:
                        print(f"  {pid}: ERROR — {e}")

    passed = sum(results.values())
    print(f"\n{'='*55}\n{passed}/{len(results)} task.md + starter.cc generated")
    failed = [pid for pid, ok in results.items() if not ok]
    if failed:
        print(f"Failed: {failed[:20]}{'...' if len(failed) > 20 else ''}")


if __name__ == "__main__":
    main()
