#!/usr/bin/env python3
"""
Build source artifacts for each CVE-mined NPD sample.

Step 1 — tree-sitter extracts real function bodies from the fix commit
          (target function + same-file callees + cross-file callees).
          primary → reference.cc;  cross-file helpers → auxiliary.cc (raw).

Step 2 — LLM portability pass: replace project #includes with stdlib
          equivalents, inline struct/typedef definitions.  Function bodies
          are kept EXACTLY as-is.  Output: reference.cc, auxiliary.cc.

Step 3 — Body swap: replace fixed function body with vulnerable_code.
          Output: context.cc.

Step 4 — Stub target function body with // TODO.  Output: starter.cc.

Step 5 — Compile check: starter.cc (+ auxiliary.cc if present).

Usage:
  python3 build_harness_cve.py pilot10.jsonl [NPD-CVE-01 NPD-CVE-03 ...]

Requires: OPENAI_API_KEY env var; optionally GITHUB_TOKEN for higher rate limits.
"""

import io
import json
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from openai import OpenAI

# Tree-sitter extraction (replaces LLM-written function bodies)
sys.path.insert(0, str(Path(__file__).parent))
from extract_treesitter import extract_from_repo

HERE             = Path(__file__).parent
DEFAULT_SAMPLES  = HERE / "samples_cve"
MODEL            = "gpt-5-mini"

# Combined size limit for primary + auxiliary extracted code.
# VulnLLM-R has a 32K token context window; with 4K reserved for output and
# ~0.5K for prompt overhead, ~28K tokens (~112K chars at 4 chars/tok) remain
# for code. 100K chars leaves a comfortable margin for retrieval rounds.
MAX_EXTRACTED_CHARS = 100_000

# ---------------------------------------------------------------------------
# LLM prompt: portability pass only (function bodies come from tree-sitter)
# ---------------------------------------------------------------------------

STUB_SYSTEM = """\
You are a C/C++ engineer adding minimal stub implementations for undefined external functions.

You will receive source code and linker errors listing undefined symbols.
Your job: output ONLY stub function definitions that satisfy the linker.

Rules:
- Infer each function's signature from its call sites in the source code.
- void functions: empty body.
- Pointer-returning functions: return NULL.
- Integer/enum-returning functions: return 0.
- Struct-returning functions: return a zero-initialized struct (e.g. return (Foo){0};).
- Do NOT emit any #include lines or struct/type definitions.
- Do NOT stub functions that are already defined in the source.

Output ONLY the stub function definitions. No markdown, no explanation.
"""

REPAIR_SYSTEM = """\
You are a C/C++ engineer fixing compilation errors in standalone source files.

You will receive:
1. The source split into "original preamble" (the part you may change) and
   "verbatim code" (READ-ONLY — may already define structs/enums/macros).
2. The compiler errors.

Your job: output a corrected preamble that fixes all the errors.
Same rules as before:
- NEVER emit #include "..." (quoted includes) — only #include <...> is allowed.
- Do NOT add forward declarations of functions.
- Do NOT output function bodies.
- If only one file's preamble is shown, output only that preamble.
- If two preambles are shown (separated by // ===== auxiliary =====), output both
  with the same separator between them.
- For any undefined identifier (constant, macro, enum value): define it with a
  plausible stub (#define FOO 0, or a minimal enum/struct).

Output ONLY the corrected preamble(s). No markdown, no explanation.
"""

PORTABILITY_SYSTEM = """\
You are a C/C++ engineer making extracted source code standalone and compilable.

You receive one or two C/C++ source files, each shown in two sections:
  - "original preamble": the broken #include directives you must replace.
  - "verbatim code": the real function bodies (and any top-level declarations
    already present). This section is READ-ONLY and will be appended unchanged.

Your ONLY job: output a replacement for the "original preamble" section —
the #include directives, struct/typedef definitions, and macro definitions
needed to make the code compile.
Do NOT output any function bodies.
CRITICAL: Do NOT redefine anything already defined in the "verbatim code"
section — structs, enums, typedefs, or macros already present there must NOT
appear in your preamble output, or they will cause redeclaration errors.

Rules:
1. Replace each project #include with standard-library includes and/or inline
   struct/typedef definitions for types the code actually uses.
   NEVER emit #include "..." (quoted includes) — only #include <...> is allowed.
   If a type comes from a project header, define it inline instead.
2. Derive struct fields by reading how the code uses them (ptr->field, ptr.field).
   Provide full struct definitions — forward declarations alone are not enough.
3. For logging/debug/assertion macros: define them as ((void)0) or nothing.
4. For IS_ERR / PTR_ERR / ERR_PTR kernel macros: write faithful implementations
   using intptr_t casts.
5. For enums or constants used in the code but not defined, define them as
   integer constants (#define FOO 0) or a minimal enum.
6. Define all shared types in the PRIMARY preamble only.
   The AUXILIARY preamble must NOT redefine anything already in the primary.
7. Do NOT add a main() function, any function bodies, or forward declarations
   of functions — the function bodies will be appended verbatim after the preamble
   and will provide their own declarations.
8. CRITICAL — inline method bodies: For class methods defined inline in the
   preamble (accessors, lookup functions, constructors), implement the REAL
   behavior using standard library types (std::map, std::vector, std::string,
   std::unordered_map, etc.). Do NOT stub a lookup or accessor to
   unconditionally return nullptr/NULL — that makes any NPD either trivially
   detectable or completely unreachable, corrupting the benchmark.
   Example — BAD:   const_iterator findKey(const K&) const { return end(); }
   Example — GOOD:  const_iterator findKey(const K& k) const {
                        auto it = entries_.find(k.key_);
                        return it == entries_.end() ? end() : const_iterator(&it->second); }
                    (with entries_ declared as std::map<std::string, Entry> entries_;)
   Similarly, object fields that hold pointers must be set by the constructor
   to a valid allocated object (or derived from real member state), not left as
   nullptr unconditionally.

Output format (STRICT — no markdown, no explanation):
- If only a primary file was given: output the primary preamble only.
- If both files were given: output the primary preamble, then exactly this line:
    // ===== auxiliary =====
  then the auxiliary preamble.

--- EXAMPLE 1: struct fields + macros ---
INPUT (primary only):
  #include "core/list.h"
  #include "debug/log.h"

  static Node *find_node(List *list, int id) {
      LOG_DEBUG("searching id=%d", id);
      Node *cur = list->head;
      while (cur) {
          if (cur->id == id) return cur;
          cur = cur->next;
      }
      return NULL;
  }

OUTPUT:
  #include <stddef.h>
  #define LOG_DEBUG(...) ((void)0)
  typedef struct Node { int id; struct Node *next; } Node;
  typedef struct { Node *head; } List;

--- EXAMPLE 2: enum constants used in switch ---
INPUT (primary only):
  #include "codec/defs.h"

  int codec_process(Codec *c, int type) {
      switch (type) {
          case CODEC_TYPE_VIDEO: return c->video_fn(c);
          case CODEC_TYPE_AUDIO: return c->audio_fn(c);
          default: return -1;
      }
  }

OUTPUT:
  #include <stddef.h>
  #define CODEC_TYPE_VIDEO 0
  #define CODEC_TYPE_AUDIO 1
  typedef struct Codec { int (*video_fn)(struct Codec *); int (*audio_fn)(struct Codec *); } Codec;

--- EXAMPLE 3: two files ---
INPUT (primary):
  #include "net/buf.h"

  int buf_read(Buffer *buf, void *dst, size_t n) {
      if (buf->pos + n > buf->len) return -1;
      memcpy(dst, buf->data + buf->pos, n);
      buf->pos += n;
      return 0;
  }

INPUT (auxiliary):
  #include "net/buf.h"

  Buffer *buf_new(size_t cap) {
      Buffer *b = hi_malloc(sizeof(*b));
      if (!b) return NULL;
      b->data = hi_malloc(cap);
      b->len = cap; b->pos = 0;
      return b;
  }

OUTPUT:
  #include <string.h>
  #include <stdlib.h>
  #include <stddef.h>
  typedef struct { unsigned char *data; size_t len, pos; } Buffer;
  // ===== auxiliary =====
  #define hi_malloc malloc
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
    """Infer 'c' or 'cpp' from the lang field or file extension."""
    lang = row.get("lang")
    if lang in ("c", "cpp"):
        return lang
    ext = Path(row.get("file", row.get("file_path", ""))).suffix.lower()
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


def _stub_body(func_name: str, vuln_code: str, lang: str = "c") -> str:
    if _return_type_is_void(vuln_code):
        ret = ""
    elif lang == "cpp":
        ret = "    return {};\n"   # works for pointers, smart ptrs, structs, ints
    else:
        ret = "    return 0;\n"
    return f"    // TODO: Implement {func_name}.\n{ret}"


def _sig_fragment(row: dict) -> str:
    """First non-empty line of vulnerable_code — the actual function definition line."""
    for line in (row.get("vulnerable_code") or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:80]
    return row.get("func_name", "")


# ---------------------------------------------------------------------------
# LLM portability pass (tree-sitter provides function bodies; LLM fixes includes/types)
# ---------------------------------------------------------------------------

def _strip_fences(raw: str) -> str:
    raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```$",       "", raw, flags=re.MULTILINE)
    # Remove any quoted includes the LLM emitted despite the rule — they can
    # never compile standalone and cause fatal errors.
    raw = re.sub(r'^\s*#\s*include\s*"[^"]*"\s*$', "", raw, flags=re.MULTILINE)
    return raw.strip()


_AUX_SEPARATOR = "// ===== auxiliary ====="
_PRINT_LOCK    = threading.Lock()


def _quoted_include_re():
    return re.compile(r'^\s*#\s*include\s*"[^"]*"\s*$', re.MULTILINE)


def strip_project_includes(src: str) -> str:
    """Remove #include "..." lines — they can never resolve standalone."""
    return _quoted_include_re().sub("", src)


def _split_preamble(src: str, lang: str) -> tuple[str, str]:
    """Split src into (preamble, functions) at the first function_definition.

    Uses tree-sitter to find the byte offset of the first function_definition
    node so the split is exact. Falls back to returning ("", src) if no
    function is found (shouldn't happen for well-formed extracted code).
    """
    from tree_sitter import Language, Parser
    import tree_sitter_c, tree_sitter_cpp
    ts_lang = Language(tree_sitter_cpp.language() if lang == "cpp" else tree_sitter_c.language())
    parser = Parser(ts_lang)
    src_bytes = src.encode("utf-8")
    tree = parser.parse(src_bytes)
    for node in tree.root_node.children:
        if node.type == "function_definition":
            preamble = src_bytes[:node.start_byte].decode("utf-8", errors="replace")
            functions = src_bytes[node.start_byte:].decode("utf-8", errors="replace")
            return preamble.strip(), functions.strip()
    return "", src.strip()


def _build_user_msg(lang: str,
                    primary_preamble: str, primary_fns: str,
                    aux_preamble: str | None = None, aux_fns: str | None = None) -> str:
    """Format the user message showing the original preamble vs read-only verbatim code."""
    lang_label = "C++" if lang == "cpp" else "C"
    parts = [f"Language: {lang_label}\n"]
    parts.append("=== primary: original preamble (REPLACE THIS) ===")
    parts.append(primary_preamble or "(empty)")
    parts.append("=== primary: verbatim code (READ-ONLY — may already define types/enums) ===")
    parts.append(primary_fns)
    if aux_preamble is not None and aux_fns is not None:
        parts.append("=== auxiliary: original preamble (REPLACE THIS) ===")
        parts.append(aux_preamble or "(empty)")
        parts.append("=== auxiliary: verbatim code (READ-ONLY — may already define types/enums) ===")
        parts.append(aux_fns)
    return "\n".join(parts)


def portability_pass(raw_primary: str, lang: str, client: OpenAI,
                     raw_auxiliary: str | None = None,
                     initial_errors: str | None = None) -> tuple[str, str | None] | None:
    """Make tree-sitter extracted code compilable in one LLM call.

    The LLM outputs only replacement preambles (includes/typedefs/macros).
    Function bodies are taken verbatim from the raw files and appended.
    Returns (primary_src, auxiliary_src | None) or None on failure.
    """
    primary_preamble, primary_fns = _split_preamble(raw_primary, lang)
    if raw_auxiliary:
        aux_preamble, aux_fns = _split_preamble(raw_auxiliary, lang)
        user_msg = _build_user_msg(lang, primary_preamble, primary_fns, aux_preamble, aux_fns)
    else:
        user_msg = _build_user_msg(lang, primary_preamble, primary_fns)
        aux_preamble = aux_fns = None

    if initial_errors:
        user_msg += f"\n\n=== compiler errors from stripping project includes ===\n{initial_errors}"

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": PORTABILITY_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
        )
        raw = _strip_fences(resp.choices[0].message.content or "")
    except Exception as e:
        print(f"    LLM portability error: {e}")
        return None

    # Split LLM output into preambles
    if raw_auxiliary and _AUX_SEPARATOR in raw:
        parts = raw.split(_AUX_SEPARATOR, 1)
        new_primary_preamble = parts[0].strip()
        new_aux_preamble     = parts[1].strip()
    elif raw_auxiliary:
        print(f"    WARN — auxiliary separator missing; using full LLM output as primary preamble")
        new_primary_preamble = raw.strip()
        new_aux_preamble     = ""
    else:
        new_primary_preamble = raw.strip()
        new_aux_preamble     = None

    # Reconstruct: LLM preamble + verbatim function bodies from raw files
    primary_out = new_primary_preamble + "\n\n" + primary_fns

    if raw_auxiliary is not None:
        auxiliary_out = (new_aux_preamble or "") + "\n\n" + aux_fns
        return primary_out, auxiliary_out

    return primary_out, None


# ---------------------------------------------------------------------------
# Step 4: compile check
# ---------------------------------------------------------------------------

def compile_check(path: Path, lang: str, extra_srcs: str = "") -> tuple[bool, str]:
    """Returns (success, stderr). Prints errors on failure."""
    compiler = "g++" if lang == "cpp" else "gcc"
    flags    = "-std=c++17" if lang == "cpp" else "-std=c11 -x c"
    srcs     = f"{path} {extra_srcs}".strip()
    r = subprocess.run(
        f"{compiler} {flags} -w -fsyntax-only {srcs}",
        shell=True, capture_output=True, text=True, timeout=30,
    )
    return r.returncode == 0, r.stderr


def link_check(path: Path, lang: str, extra_srcs: str = "") -> tuple[bool, str]:
    """Full link (not syntax-only). Returns (success, stderr)."""
    import tempfile
    compiler = "g++" if lang == "cpp" else "gcc"
    flags    = "-std=c++17" if lang == "cpp" else "-std=c11 -x c"
    srcs     = f"{path} {extra_srcs}".strip()
    tmp_bin  = Path(tempfile.mktemp(suffix=".out", dir="/tmp"))
    r = subprocess.run(
        f"{compiler} {flags} -w {srcs} -o {tmp_bin} -lm",
        shell=True, capture_output=True, text=True, timeout=60,
    )
    tmp_bin.unlink(missing_ok=True)
    return r.returncode == 0, r.stderr


def linker_stub_pass(primary_src: str, auxiliary_src: str | None,
                     link_errors: str, lang: str, client: OpenAI) -> str | None:
    """Ask the LLM to generate stub implementations for undefined symbols."""
    user_msg = (
        f"Language: {'C++' if lang == 'cpp' else 'C'}\n\n"
        f"=== source code ===\n{primary_src}\n"
        + (f"\n=== auxiliary ===\n{auxiliary_src}\n" if auxiliary_src else "")
        + f"\n=== linker errors ===\n{link_errors}"
    )
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": STUB_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
        )
        raw = _strip_fences(resp.choices[0].message.content or "")
        return raw.strip() or None
    except Exception as e:
        print(f"    LLM stub error: {e}")
        return None


def preamble_repair(primary_src: str, auxiliary_src: str | None,
                    errors: str, lang: str, client: OpenAI) -> tuple[str, str | None] | None:
    """Ask the LLM to fix the preamble(s) given compiler errors.

    Sends the current preamble(s) + error text; LLM returns corrected preamble(s).
    Function bodies are kept verbatim — only preambles are replaced.
    """
    primary_preamble, primary_fns = _split_preamble(primary_src, lang)

    if auxiliary_src is not None:
        aux_preamble, aux_fns = _split_preamble(auxiliary_src, lang)
    else:
        aux_preamble = aux_fns = None

    base_msg = _build_user_msg(lang, primary_preamble, primary_fns, aux_preamble, aux_fns)
    user_msg = base_msg + f"\n\n=== compiler errors ===\n{errors}"

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": REPAIR_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
        )
        raw = _strip_fences(resp.choices[0].message.content or "")
    except Exception as e:
        print(f"    LLM repair error: {e}")
        return None

    if auxiliary_src is not None and _AUX_SEPARATOR in raw:
        parts = raw.split(_AUX_SEPARATOR, 1)
        new_primary_preamble = parts[0].strip()
        new_aux_preamble     = parts[1].strip()
    elif auxiliary_src is not None:
        print(f"    WARN — repair: auxiliary separator missing; using output as primary preamble")
        new_primary_preamble = raw.strip()
        new_aux_preamble     = aux_preamble
    else:
        new_primary_preamble = raw.strip()
        new_aux_preamble     = None

    new_primary = new_primary_preamble + "\n\n" + primary_fns
    if aux_fns is not None:
        new_auxiliary = (new_aux_preamble or "") + "\n\n" + aux_fns
        return new_primary, new_auxiliary
    return new_primary, None


# ---------------------------------------------------------------------------
# Build one sample
# ---------------------------------------------------------------------------

def build_one_ts_only(row: dict, samples_dir: Path = DEFAULT_SAMPLES,
                      token: str | None = None) -> bool:
    """Tree-sitter extraction only — no LLM, no compile check. Saves raw_primary.cc."""
    pid       = row.get("pilot_id", row.get("func_name", "?"))
    lang      = _infer_lang(row)
    out_dir   = samples_dir / pid
    out_dir.mkdir(parents=True, exist_ok=True)

    if not row.get("vulnerable_code"):
        print(f"  {pid}: SKIP — missing vulnerable_code")
        return False

    result = extract_from_repo(row, token=token, split_auxiliary=True)
    if result is None:
        print(f"  {pid}: FAIL — tree-sitter extraction failed")
        return False
    raw_primary, raw_auxiliary = result
    if not raw_primary:
        print(f"  {pid}: FAIL — tree-sitter returned empty primary")
        return False

    total_chars = len(raw_primary) + len(raw_auxiliary or "")
    if total_chars > MAX_EXTRACTED_CHARS:
        print(f"  {pid}: SKIP — too large ({total_chars:,} chars)")
        return False

    print(f"  {pid}: OK — {len(raw_primary.splitlines())} primary lines"
          + (f", {len((raw_auxiliary or '').splitlines())} auxiliary lines"
             if raw_auxiliary else ""))
    (out_dir / "raw_primary.cc").write_text(raw_primary)
    if raw_auxiliary:
        (out_dir / "raw_auxiliary.cc").write_text(raw_auxiliary)

    meta = {
        "pilot_id":    pid,
        "cve_id":      row.get("cve_id", ""),
        "repo_url":    row.get("repo_url", ""),
        "commit_hash": row.get("commit_hash", ""),
        "file":        row.get("file", row.get("file_path", "")),
        "function":    row.get("func_name", row.get("function", "")),
        "lang":        lang,
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2))
    return True


def build_one(row: dict, client: OpenAI, skip_extract: bool = False,
              from_raw: bool = False,
              samples_dir: Path = DEFAULT_SAMPLES,
              token: str | None = None) -> bool:
    pid       = row["pilot_id"]
    func_name = row.get("func_name", row.get("function", ""))
    vuln_code = row.get("vulnerable_code", "")
    lang      = _infer_lang(row)
    out_dir   = samples_dir / pid
    out_dir.mkdir(parents=True, exist_ok=True)

    # Buffer all output so parallel threads don't interleave mid-sample.
    buf = io.StringIO()
    log = lambda *a: print(*a, file=buf)

    if not vuln_code:
        log(f"  {pid}: SKIP — missing vulnerable_code")
        with _PRINT_LOCK: print(buf.getvalue(), end="")
        return False

    # ── Step 1: tree-sitter extraction (real function bodies from repo) ───────
    cached_ref      = out_dir / "reference.cc"
    cached_aux      = out_dir / "auxiliary.cc"
    raw_primary_f   = out_dir / "raw_primary.cc"
    raw_auxiliary_f = out_dir / "raw_auxiliary.cc"

    if skip_extract and cached_ref.exists():
        log(f"  reusing cached reference.cc")
        extracted = cached_ref.read_text()
        auxiliary = cached_aux.read_text() if cached_aux.exists() else None
    elif from_raw:
        if not raw_primary_f.exists():
            log(f"  {pid}: SKIP — no raw_primary.cc (treesitter failed or too large)")
            with _PRINT_LOCK: print(buf.getvalue(), end="")
            return False
        log(f"  reusing raw_primary.cc (skipping GitHub fetch)")
        raw_primary   = raw_primary_f.read_text()
        raw_auxiliary = raw_auxiliary_f.read_text() if raw_auxiliary_f.exists() else None

        # ── Step 2a: try compiling stripped raw directly ──────────────────────
        stripped_primary   = strip_project_includes(raw_primary)
        stripped_auxiliary = strip_project_includes(raw_auxiliary) if raw_auxiliary else None
        tmp_p = out_dir / "_tmp_stripped.cc"
        tmp_a = out_dir / "_tmp_stripped_aux.cc"
        tmp_p.write_text(stripped_primary)
        if stripped_auxiliary:
            tmp_a.write_text(stripped_auxiliary)
        extra_tmp = str(tmp_a) if stripped_auxiliary else ""
        raw_ok, raw_errors = compile_check(tmp_p, lang, extra_srcs=extra_tmp)
        tmp_p.unlink(missing_ok=True)
        if stripped_auxiliary:
            tmp_a.unlink(missing_ok=True)

        if raw_ok:
            # Stripped raw already compiles — use it directly, no LLM needed.
            log(f"  raw stripped: compile OK (no LLM needed) ✓")
            extracted = stripped_primary
            auxiliary = stripped_auxiliary
        else:
            # ── Step 2b: LLM portability pass with real errors ────────────────
            aux_label = " + auxiliary" if raw_auxiliary else ""
            log(f"  portability pass (primary{aux_label}, with compile errors)...")
            result = portability_pass(raw_primary, lang, client,
                                      raw_auxiliary=raw_auxiliary,
                                      initial_errors=raw_errors)
            if not result:
                log(f"  {pid}: FAIL — portability pass returned nothing")
                with _PRINT_LOCK: print(buf.getvalue(), end="")
                return False
            extracted, auxiliary = result
    else:
        log(f"  tree-sitter: fetching real function bodies from repo...")
        result = extract_from_repo(row, token=token, split_auxiliary=True)
        if result is None:
            log(f"  {pid}: FAIL — tree-sitter extraction failed")
            with _PRINT_LOCK: print(buf.getvalue(), end="")
            return False
        raw_primary, raw_auxiliary = result
        if not raw_primary:
            log(f"  {pid}: FAIL — tree-sitter returned empty primary")
            with _PRINT_LOCK: print(buf.getvalue(), end="")
            return False
        log(f"  tree-sitter: {len(raw_primary.splitlines())} primary lines"
            + (f", {len(raw_auxiliary.splitlines())} auxiliary lines"
               if raw_auxiliary else ""))

        total_chars = len(raw_primary) + len(raw_auxiliary or "")
        if total_chars > MAX_EXTRACTED_CHARS:
            log(f"  {pid}: SKIP — extracted code too large "
                f"({total_chars:,} chars > {MAX_EXTRACTED_CHARS:,} limit)")
            with _PRINT_LOCK: print(buf.getvalue(), end="")
            return False

        stripped_primary   = strip_project_includes(raw_primary)
        stripped_auxiliary = strip_project_includes(raw_auxiliary) if raw_auxiliary else None
        tmp_p = out_dir / "_tmp_stripped.cc"
        tmp_a = out_dir / "_tmp_stripped_aux.cc"
        tmp_p.write_text(stripped_primary)
        if stripped_auxiliary:
            tmp_a.write_text(stripped_auxiliary)
        extra_tmp = str(tmp_a) if stripped_auxiliary else ""
        raw_ok, raw_errors = compile_check(tmp_p, lang, extra_srcs=extra_tmp)
        tmp_p.unlink(missing_ok=True)
        if stripped_auxiliary:
            tmp_a.unlink(missing_ok=True)

        if raw_ok:
            log(f"  raw stripped: compile OK (no LLM needed) ✓")
            extracted = stripped_primary
            auxiliary = stripped_auxiliary
        else:
            aux_label = " + auxiliary" if raw_auxiliary else ""
            log(f"  portability pass (primary{aux_label}, with compile errors)...")
            result = portability_pass(raw_primary, lang, client,
                                      raw_auxiliary=raw_auxiliary,
                                      initial_errors=raw_errors)
            if not result:
                log(f"  {pid}: FAIL — portability pass returned nothing")
                with _PRINT_LOCK: print(buf.getvalue(), end="")
                return False
            extracted, auxiliary = result

    # ── Steps 3-4: body swap → context.cc / stub → starter.cc ──────────────
    sig       = _sig_fragment(row)
    vuln_body = vuln_code.split('{', 1)[-1].rsplit('}', 1)[0]

    def _write_derived(ref: str, aux: str | None):
        context_cc = replace_function_body(ref, sig, vuln_body + "\n")
        if context_cc == ref:
            log(f"  {pid}: WARN — body swap had no effect; context.cc == reference.cc")
        (out_dir / "context.cc").write_text(context_cc)

        stub       = _stub_body(func_name, vuln_code, lang=lang)
        starter_cc = replace_function_body(ref, sig, stub)
        if starter_cc == ref:
            log(f"  {pid}: WARN — stub replacement had no effect (sig not found)")
        (out_dir / "starter.cc").write_text(starter_cc)

        (out_dir / "reference.cc").write_text(ref)
        if aux:
            (out_dir / "auxiliary.cc").write_text(aux)
        elif (out_dir / "auxiliary.cc").exists():
            (out_dir / "auxiliary.cc").unlink()

    _write_derived(extracted, auxiliary)

    # ── Step 5: metadata ─────────────────────────────────────────────────────
    meta = {
        "pilot_id":    pid,
        "cve_id":      row.get("cve_id", ""),
        "repo_url":    row.get("repo_url", ""),
        "commit_hash": row.get("commit_hash", ""),
        "file":        row.get("file", row.get("file_path", "")),
        "function":    func_name,
        "lang":        lang,
        "source":      row.get("source", ""),
        "diff_ptrs":   row.get("diff_ptrs", []),
        "extra_files": row.get("extra_files", []),
        "commit_url":  (f"{row.get('repo_url','')}/commit/{row.get('commit_hash','')}"
                        if row.get("repo_url") and row.get("commit_hash") else None),
        "nvd_url":     (f"https://nvd.nist.gov/vuln/detail/{row['cve_id']}"
                        if row.get("cve_id") else None),
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2))

    def _log_compile_fail(errs: str):
        log(f"    compile FAILED:")
        for line in errs.splitlines()[:15]:
            log(f"      {line}")

    # ── Step 6: compile + up to 2 repair rounds ──────────────────────────────
    extra_srcs = str(out_dir / "auxiliary.cc") if auxiliary else ""
    ok, errors = compile_check(out_dir / "starter.cc", lang, extra_srcs=extra_srcs)
    if not ok:
        _log_compile_fail(errors)

    for repair_round in range(1, 3):
        if ok:
            break
        log(f"  repair round {repair_round}...")
        repaired = preamble_repair(extracted, auxiliary, errors, lang, client)
        if repaired is None:
            break
        extracted, auxiliary = repaired
        _write_derived(extracted, auxiliary)
        extra_srcs = str(out_dir / "auxiliary.cc") if auxiliary else ""
        ok, errors = compile_check(out_dir / "starter.cc", lang, extra_srcs=extra_srcs)
        if not ok:
            _log_compile_fail(errors)

    # ── Step 7: full link check + one stub round ─────────────────────────────
    if ok:
        extra_link = str(out_dir / "auxiliary.cc") if auxiliary else ""
        ok_link, link_errors = link_check(out_dir / "starter.cc", lang, extra_srcs=extra_link)
        if not ok_link:
            if "undefined reference" in link_errors:
                log(f"  link FAILED — generating stubs...")
                stubs = linker_stub_pass(extracted, auxiliary, link_errors, lang, client)
                if stubs:
                    extracted = extracted + "\n\n// ===== linker stubs =====\n" + stubs
                    _write_derived(extracted, auxiliary)
                    ok_link, link_errors = link_check(out_dir / "starter.cc", lang,
                                                      extra_srcs=extra_link)
                    if ok_link:
                        log(f"  link OK after stubs ✓")
                    else:
                        log(f"  link STILL FAILED after stubs:")
                        for line in link_errors.splitlines()[:8]:
                            log(f"    {line}")
            else:
                log(f"  link FAILED (non-stub error):")
                for line in link_errors.splitlines()[:8]:
                    log(f"    {line}")
        ok = ok_link

    if ok:
        log(f"  {pid}: compile OK ✓")

    with _PRINT_LOCK:
        print(buf.getvalue(), end="")
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
                    help="Reuse cached reference.cc instead of re-running tree-sitter + LLM")
    ap.add_argument("--from-raw", action="store_true",
                    help="Reuse raw_primary.cc / raw_auxiliary.cc from a prior --tree-sitter-only "
                         "run — skips GitHub fetch, goes straight to LLM portability pass")
    ap.add_argument("--tree-sitter-only", action="store_true",
                    help="Run tree-sitter extraction only — no LLM, no compile check. "
                         "Saves raw_primary.cc / raw_auxiliary.cc per sample.")
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES),
                    help=f"Output directory (default: {DEFAULT_SAMPLES})")
    ap.add_argument("--token", default=None,
                    help="GitHub API token for private repos / higher rate limits")
    ap.add_argument("--workers", type=int, default=1,
                    help="Parallel workers for LLM calls (default: 1)")
    args = ap.parse_args()

    import os
    token = args.token or os.environ.get("GITHUB_TOKEN")

    jsonl_path  = Path(args.jsonl)
    samples_dir = Path(args.samples_dir)
    filter_ids  = set(args.ids) if args.ids else None

    rows = [json.loads(l) for l in jsonl_path.read_text().splitlines() if l.strip()]
    if filter_ids:
        rows = [r for r in rows if r.get("pilot_id") in filter_ids]

    print(f"Processing {len(rows)} samples → {samples_dir}/ (workers={args.workers})\n")

    results = {}
    if args.tree_sitter_only:
        for row in rows:
            pid = row.get("pilot_id", "?")
            results[pid] = build_one_ts_only(row, samples_dir=samples_dir, token=token)
    else:
        client = OpenAI()

        def _run(row):
            pid = row.get("pilot_id", "?")
            with _PRINT_LOCK:
                print(f"=== {pid} ({row.get('func_name', row.get('function', ''))}) ===")
            return pid, build_one(row, client, skip_extract=args.skip_extract,
                                  from_raw=args.from_raw,
                                  samples_dir=samples_dir, token=token)

        if args.workers == 1:
            for row in rows:
                pid, ok = _run(row)
                results[pid] = ok
        else:
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

    print(f"\n{'='*50}\nSummary: {sum(results.values())}/{len(results)} succeeded")
    failed = [pid for pid, ok in results.items() if not ok]
    if failed:
        print(f"Failed ({len(failed)}): {failed[:20]}{'...' if len(failed) > 20 else ''}")
    sys.exit(0 if sum(results.values()) > 0 else 1)


if __name__ == "__main__":
    main()
