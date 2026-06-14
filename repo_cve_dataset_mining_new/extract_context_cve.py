#!/usr/bin/env python3
"""
extract_context_cve.py — Stage 1 Step 2: tree-sitter extraction for CVE NPD samples.

For each sample with repo_testsuite_pass, runs tree-sitter on the source file
from the local repo clone and writes:
  raw_primary.cc    — target function + same-file callees/callers
  raw_auxiliary.cc  — cross-file helper implementations (if any)
  metadata.json     — pilot_id, func, file, repo, commit, lang

Usage:
  python3 repo_cve_dataset_mining_new/extract_context_cve.py \\
      repo_cve_dataset_mining_new/f3_nolimit_dedup_func.jsonl \\
      --clone-dir /tmp/cve_repos_fix \\
      --samples-dir repo_cve_dataset_mining/samples_cve_fix \\
      [--workers 4]
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
import urllib.error
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, Sequence

from tree_sitter import Language, Node, Parser
import tree_sitter_c
import tree_sitter_cpp

HERE            = Path(__file__).parent
DEFAULT_SAMPLES = HERE.parent / "repo_cve_dataset_mining" / "samples_cve_fix"
DEFAULT_CLONE   = Path("/tmp/cve_repos_fix")
MAX_EXTRACTED_CHARS = 60_000

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

_LANG_C   = Language(tree_sitter_c.language())
_LANG_CPP = Language(tree_sitter_cpp.language())


def _make_parser(lang: str) -> Parser:
    return Parser(_LANG_CPP if lang == "cpp" else _LANG_C)


def _infer_lang(row: dict) -> str:
    lang = row.get("lang")
    if lang in ("c", "cpp"):
        return lang
    ext = Path(row.get("file", row.get("file_path", ""))).suffix.lower()
    return "cpp" if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh") else "c"


# ---------------------------------------------------------------------------
# Macro preprocessing
# ---------------------------------------------------------------------------

_MACRO_EXPAND = [
    (re.compile(r'\bMETHODDEF\s*\(\s*([^)]+?)\s*\)'), r'static \1'),
    (re.compile(r'\bLOCAL\s*\(\s*([^)]+?)\s*\)'),     r'static \1'),
    (re.compile(r'\bGLOBAL\s*\(\s*([^)]+?)\s*\)'),    r'\1'),
    (re.compile(r'\bEXTERN\s*\(\s*([^)]+?)\s*\)'),    r'extern \1'),
]


def _preprocess_macros(raw: str) -> str:
    for pat, repl in _MACRO_EXPAND:
        raw = pat.sub(repl, raw)
    return raw


# ---------------------------------------------------------------------------
# Source fetching
# ---------------------------------------------------------------------------

def _repo_slug(repo_url: str) -> str:
    return repo_url.rstrip("/").replace("https://github.com/", "").replace("/", "__")


def fetch_source(repo_url: str, commit: str, file_path: str,
                 token: str | None = None,
                 clone_dir: Path | None = None) -> str:
    if clone_dir is not None:
        local = clone_dir / _repo_slug(repo_url) / file_path
        if local.exists():
            return local.read_text(errors="replace")

    m = re.match(r"https?://github\.com/([^/]+/[^/]+)", repo_url)
    if not m:
        raise ValueError(f"Cannot parse repo URL: {repo_url}")
    url = f"https://raw.githubusercontent.com/{m.group(1)}/{commit}/{file_path}"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} fetching {url}") from e


# ---------------------------------------------------------------------------
# Tree-sitter helpers
# ---------------------------------------------------------------------------

def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _iter_named(node: Node) -> Iterator[Node]:
    for child in node.children:
        if child.is_named:
            yield child


def _fn_name_from_declarator(decl: Node, src: bytes) -> str | None:
    if decl is None:
        return None
    if decl.type == "function_declarator":
        inner = decl.child_by_field_name("declarator")
        return _fn_name_from_declarator(inner, src)
    if decl.type in ("identifier", "field_identifier", "type_identifier"):
        return src[decl.start_byte:decl.end_byte].decode()
    if decl.type in ("pointer_declarator", "reference_declarator",
                     "abstract_pointer_declarator"):
        inner = decl.child_by_field_name("declarator")
        return _fn_name_from_declarator(inner, src)
    if decl.type == "qualified_identifier":
        name = decl.child_by_field_name("name")
        result = _fn_name_from_declarator(name, src)
        if result:
            return result
        scope = decl.child_by_field_name("scope")
        return _fn_name_from_declarator(scope, src)
    if decl.type == "destructor_name":
        return _text(decl, src)
    if decl.type == "operator_name":
        return _text(decl, src)
    return None


def _get_fn_name(fn_def: Node, src: bytes) -> str | None:
    decl = fn_def.child_by_field_name("declarator")
    return _fn_name_from_declarator(decl, src)


def _collect_calls(node: Node, src: bytes) -> set[str]:
    result: set[str] = set()
    stack = list(node.children)
    while stack:
        n = stack.pop()
        if n.type == "call_expression":
            fn_node = n.child_by_field_name("function")
            if fn_node is not None:
                if fn_node.type == "identifier":
                    result.add(src[fn_node.start_byte:fn_node.end_byte].decode())
                elif fn_node.type == "field_expression":
                    field = fn_node.child_by_field_name("field")
                    if field:
                        result.add(src[field.start_byte:field.end_byte].decode())
        if n.type != "function_definition":
            stack.extend(n.children)
    return result


def _collect_free_calls(node: Node, src: bytes) -> set[str]:
    result: set[str] = set()
    stack = list(node.children)
    while stack:
        n = stack.pop()
        if n.type == "call_expression":
            fn_node = n.child_by_field_name("function")
            if fn_node is not None and fn_node.type in (
                "identifier", "qualified_identifier", "template_function",
            ):
                name = _fn_name_from_declarator(fn_node, src)
                if name:
                    result.add(name)
        if n.type != "function_definition":
            stack.extend(n.children)
    return result


def _collect_identifiers(node: Node, src: bytes) -> set[str]:
    result: set[str] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("identifier", "type_identifier", "field_identifier"):
            result.add(src[n.start_byte:n.end_byte].decode())
        stack.extend(n.children)
    return result


# ---------------------------------------------------------------------------
# Item catalog
# ---------------------------------------------------------------------------

class _Item:
    __slots__ = ("kind", "name", "node", "src_text")

    def __init__(self, kind: str, name: str, node: Node, src: bytes,
                 src_text_override: str | None = None):
        self.kind     = kind
        self.name     = name
        self.node     = node
        self.src_text = src_text_override if src_text_override is not None \
                        else _text(node, src)


def _strip_method_bodies(node: Node, src: bytes) -> str:
    raw = _text(node, src)
    result_parts: list[str] = []
    pos = node.start_byte

    def _process_field_list(flist: Node) -> None:
        nonlocal pos
        for child in flist.children:
            if child.type == "function_definition":
                body = child.child_by_field_name("body")
                if body:
                    sig_end = body.start_byte
                    result_parts.append(src[pos:sig_end].decode("utf-8", errors="replace"))
                    result_parts.append(";")
                    pos = child.end_byte
            elif child.type in ("class_specifier", "struct_specifier"):
                result_parts.append(src[pos:child.start_byte].decode("utf-8", errors="replace"))
                result_parts.append(_strip_method_bodies(child, src))
                pos = child.end_byte

    for child in node.children:
        if child.type == "field_declaration_list":
            result_parts.append(src[pos:child.start_byte].decode("utf-8", errors="replace"))
            pos = child.start_byte
            _process_field_list(child)
        elif child.type == "declaration_list":
            result_parts.append(src[pos:child.start_byte].decode("utf-8", errors="replace"))
            pos = child.start_byte
            _process_field_list(child)

    result_parts.append(src[pos:node.end_byte].decode("utf-8", errors="replace"))
    return "".join(result_parts)


def _catalog(tree_root: Node, src: bytes) -> list[_Item]:
    items: list[_Item] = []

    def _visit(node: Node, depth: int = 0) -> None:
        t = node.type
        if t == "function_definition":
            type_child = node.child_by_field_name("type")
            if type_child is not None:
                type_text = src[type_child.start_byte:type_child.end_byte].decode(errors="replace")
                if type_text in ("namespace", "class", "struct", "union"):
                    body = node.child_by_field_name("body")
                    if body is not None:
                        for child in body.children:
                            _visit(child, depth + 1)
                    return
            name = _get_fn_name(node, src) or ""
            items.append(_Item("fn", name, node, src))
            return
        if t in ("preproc_def", "preproc_function_def"):
            name_node = node.child_by_field_name("name")
            name = _text(name_node, src) if name_node else ""
            items.append(_Item("macro", name, node, src))
            return
        if t == "preproc_include":
            items.append(_Item("include", "", node, src))
            return
        if t in ("type_definition", "struct_specifier", "union_specifier", "enum_specifier"):
            name = ""
            for child in node.children:
                if child.type in ("type_identifier", "identifier"):
                    name = _text(child, src)
                    break
            stripped = _strip_method_bodies(node, src)
            items.append(_Item("type", name, node, src, stripped))
            for child in node.children:
                if child.type == "field_declaration_list":
                    for gc in child.children:
                        _visit(gc, depth + 1)
            return
        if t == "class_specifier":
            name = ""
            name_node = node.child_by_field_name("name")
            if name_node:
                name = _text(name_node, src)
            stripped = _strip_method_bodies(node, src)
            items.append(_Item("type", name, node, src, stripped))
            for child in node.children:
                if child.type == "field_declaration_list":
                    for gc in child.children:
                        _visit(gc, depth + 1)
            return
        if t == "declaration":
            name = ""
            for child in node.children:
                if child.type in ("type_identifier", "identifier"):
                    name = _text(child, src)
                    break
            items.append(_Item("type", name, node, src))
            return
        if t in ("namespace_definition", "linkage_specification"):
            for child in node.children:
                if child.type == "declaration_list":
                    for gc in child.children:
                        _visit(gc, depth + 1)
            return
        if t in ("preproc_ifdef", "preproc_if", "preproc_else",
                 "preproc_elif", "preproc_elifdef"):
            for child in node.children:
                _visit(child, depth=depth)
            return
        if t == "comment":
            return
        if t == "ERROR":
            # Tree-sitter failed to parse this subtree — recurse anyway
            for child in node.children:
                _visit(child, depth=depth)
            return
        if depth == 0:
            items.append(_Item("other", "", node, src))

    for child in tree_root.children:
        _visit(child, depth=0)

    return items


# ---------------------------------------------------------------------------
# Cross-file resolution
# ---------------------------------------------------------------------------

def _project_include_paths(items: list[_Item], primary_file: str) -> list[str]:
    candidates: list[str] = []
    for ext, hdr in [(".cc", ".h"), (".cpp", ".h"), (".c", ".h")]:
        if primary_file.endswith(ext):
            candidates.append(primary_file[: -len(ext)] + hdr)
            break
    primary_dir = str(Path(primary_file).parent)
    for item in items:
        if item.kind != "include":
            continue
        m = re.search(r'#\s*include\s+"([^"]+)"', item.src_text)
        if not m:
            continue
        inc = m.group(1)
        for path in (inc, str(Path(primary_dir) / inc)):
            if path not in candidates:
                candidates.append(path)
            for h_ext, impl_ext in ((".h", ".c"), (".h", ".cc"), (".hpp", ".cpp")):
                if path.endswith(h_ext):
                    impl = path[: -len(h_ext)] + impl_ext
                    if impl not in candidates:
                        candidates.append(impl)
    return candidates


def _fetch_and_extract(repo_url, commit, file_path, needed, parser, token,
                       clone_dir=None):
    try:
        raw = fetch_source(repo_url, commit, file_path, token, clone_dir)
    except Exception:
        return [], set()
    src = _preprocess_macros(raw).encode("utf-8", errors="replace")
    tree = parser.parse(src)
    extra_items = _catalog(tree.root_node, src)
    extra_fn_by_name = {it.name: it for it in extra_items if it.kind == "fn"}
    found = needed & extra_fn_by_name.keys()
    if not found:
        return [], set()
    all_needed: set[str] = set()
    for seed in found:
        all_needed |= _transitive_callees(seed, extra_fn_by_name, src)
    all_needed &= extra_fn_by_name.keys()
    result_items = [it for it in extra_items if it.kind == "fn" and it.name in all_needed]
    result_items += [it for it in extra_items if it.kind in ("type", "macro", "include")]
    return result_items, found


def _fetch_quoted_includes(repo_url, commit, path, token, clone_dir=None):
    try:
        raw = fetch_source(repo_url, commit, path, token, clone_dir)
    except Exception:
        return []
    return re.findall(r'#\s*include\s+"([^"]+)"', raw)


def _resolve_cross_file_callees(unresolved, items, fn_by_name, repo_url, commit,
                                primary_file, parser, token, extra_files=(),
                                clone_dir=None):
    remaining  = set(unresolved)
    new_items: list[_Item] = []
    resolved:  set[str]    = set()
    candidate_paths = list(extra_files) + _project_include_paths(items, primary_file)
    seen_paths: set[str] = set()
    while candidate_paths and remaining:
        path = candidate_paths.pop(0)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        found_items, found_names = _fetch_and_extract(
            repo_url, commit, path, remaining, parser, token, clone_dir)
        if found_names:
            print(f"    cross-file: {path} → {sorted(found_names)}")
            new_items.extend(found_items)
            resolved |= found_names
            remaining -= found_names
        if path.endswith(".h") or path.endswith(".hpp"):
            primary_dir = str(Path(primary_file).parent)
            for inc in _fetch_quoted_includes(repo_url, commit, path, token, clone_dir):
                for base in (inc, str(Path(primary_dir) / inc)):
                    if base not in seen_paths:
                        candidate_paths.append(base)
                    for h_ext, impl_ext in ((".h", ".c"), (".h", ".cc"), (".hpp", ".cpp")):
                        if base.endswith(h_ext):
                            impl = base[: -len(h_ext)] + impl_ext
                            if impl not in seen_paths:
                                candidate_paths.append(impl)
    return new_items, resolved


def _unresolved_callees(fn_names, fn_by_name, src):
    unresolved: set[str] = set()
    for name in fn_names:
        item = fn_by_name.get(name)
        if item is None:
            continue
        for callee in _collect_free_calls(item.node, src):
            if callee not in fn_by_name:
                unresolved.add(callee)
    return unresolved


def _transitive_callees(start_name, fn_by_name, src):
    visited: set[str] = set()
    queue = deque([start_name])
    while queue:
        name = queue.popleft()
        if name in visited:
            continue
        visited.add(name)
        item = fn_by_name.get(name)
        if item is None:
            continue
        for callee in _collect_calls(item.node, src):
            if callee not in visited and callee in fn_by_name:
                queue.append(callee)
    return visited


def _find_callers(target, fn_by_name, src):
    result: set[str] = set()
    for name, item in fn_by_name.items():
        if name == target:
            continue
        if target in _collect_calls(item.node, src):
            result.add(name)
    return result


def _needed_type_names(fn_names, fn_by_name, src):
    ids: set[str] = set()
    for name in fn_names:
        item = fn_by_name.get(name)
        if item:
            ids.update(_collect_identifiers(item.node, src))
    return ids


def _assemble_auxiliary(fn_names, items):
    parts: list[str] = []
    for item in items:
        if item.kind in ("include", "macro", "type"):
            parts.append(item.src_text)
        elif item.kind == "fn" and item.name in fn_names:
            parts.append(item.src_text)
    return "\n\n".join(p.strip() for p in parts if p.strip())


def _assemble(fn_names, items, src, target_name):
    fn_by_name  = {it.name: it for it in items if it.kind == "fn"}
    needed_ids  = _needed_type_names(fn_names, fn_by_name, src)
    parts: list[str] = []
    for item in items:
        if item.kind == "include":
            parts.append(item.src_text)
        elif item.kind == "macro":
            parts.append(item.src_text)
        elif item.kind == "type":
            type_ids = _collect_identifiers(item.node, src)
            if item.name in needed_ids or type_ids & needed_ids:
                parts.append(item.src_text)
        elif item.kind == "fn" and item.name in fn_names:
            parts.append(item.src_text)
        elif item.kind == "other":
            other_ids = _collect_identifiers(item.node, src)
            if other_ids & needed_ids:
                parts.append(item.src_text)
    return "\n\n".join(p.strip() for p in parts if p.strip())


# ---------------------------------------------------------------------------
# Public extraction entry point
# ---------------------------------------------------------------------------

def extract_from_repo(row: dict, token: str | None = None,
                      clone_dir: Path | None = None) -> tuple[str, str | None] | None:
    """Return (primary, auxiliary|None) or None on failure."""
    repo_url  = row.get("repo_url", "")
    commit    = row.get("commit_hash", "")
    file_path = row.get("file", row.get("file_path", ""))
    func_name = row.get("function", row.get("func_name", ""))
    lang      = _infer_lang(row)
    extra_files: list[str] = row.get("extra_files", [])

    if not (repo_url and commit and file_path and func_name):
        return None

    try:
        raw = fetch_source(repo_url, commit, file_path, token, clone_dir)
    except Exception as e:
        print(f"    fetch error: {e}")
        return None

    src    = _preprocess_macros(raw).encode("utf-8", errors="replace")
    parser = _make_parser(lang)
    tree   = parser.parse(src)
    items  = _catalog(tree.root_node, src)
    fn_by_name = {it.name: it for it in items if it.kind == "fn"}

    if func_name not in fn_by_name:
        matches = [n for n in fn_by_name if n.endswith(func_name) or func_name in n]
        if matches:
            func_name = matches[0]
            print(f"    fuzzy match: using '{func_name}'")
        else:
            print(f"    '{func_name}' not found in {file_path} "
                  f"(found: {sorted(fn_by_name)[:8]})")
            return None

    callees  = _transitive_callees(func_name, fn_by_name, src)
    callers  = _find_callers(func_name, fn_by_name, src)
    fn_names = callees | callers

    unresolved = _unresolved_callees(fn_names, fn_by_name, src)
    cross_items: list[_Item] = []
    cross_fn_names: set[str] = set()
    if unresolved:
        cross_items, cross_fn_names = _resolve_cross_file_callees(
            unresolved, items, fn_by_name,
            repo_url, commit, file_path, parser, token,
            extra_files=extra_files, clone_dir=clone_dir,
        )

    primary_str   = _assemble(fn_names, items, src, func_name)
    auxiliary_str = _assemble_auxiliary(cross_fn_names, cross_items) \
                    if cross_items and cross_fn_names else None
    return primary_str, auxiliary_str


# ---------------------------------------------------------------------------
# Per-sample processing
# ---------------------------------------------------------------------------

def process_one(row: dict, samples_dir: Path, clone_dir: Path,
                token: str | None) -> tuple[str, str]:
    pid     = row.get("pilot_id", "?")
    lang    = _infer_lang(row)
    out_dir = samples_dir / pid

    if (out_dir / "raw_primary.cc").exists():
        return pid, "already_done"

    if not ((out_dir / "repo_testsuite_pass").exists()
            or (out_dir / "repo_testsuite_partial").exists()
            or (out_dir / "repo_compilable").exists()):
        return pid, "skip_not_viable"

    result = extract_from_repo(row, token=token, clone_dir=clone_dir)
    if result is None:
        print(f"  {pid}: FAIL — tree-sitter extraction failed")
        return pid, "fail"

    raw_primary, raw_auxiliary = result
    if not raw_primary:
        print(f"  {pid}: FAIL — empty primary")
        return pid, "fail"

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "raw_primary.cc").write_text(raw_primary)
    if raw_auxiliary:
        (out_dir / "raw_auxiliary.cc").write_text(raw_auxiliary)

    meta = {
        "pilot_id":    pid,
        "cve_id":      row.get("cve_id", ""),
        "repo_url":    row.get("repo_url", ""),
        "commit_hash": row.get("commit_hash", ""),
        "file":        row.get("file", row.get("file_path", "")),
        "function":    row.get("function", row.get("func_name", "")),
        "lang":        lang,
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2))

    n_aux = len((raw_auxiliary or "").splitlines())
    print(f"  {pid}: OK — {len(raw_primary.splitlines())} primary lines"
          + (f", {n_aux} auxiliary lines" if raw_auxiliary else ""))
    return pid, "ok"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Tree-sitter extraction for CVE samples")
    ap.add_argument("jsonl")
    ap.add_argument("ids", nargs="*", help="Pilot IDs to process (default: all viable)")
    ap.add_argument("--clone-dir",   default=str(DEFAULT_CLONE))
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES))
    ap.add_argument("--token",       default=None, help="GitHub token (fallback only)")
    ap.add_argument("--workers",     type=int, default=4)
    ap.add_argument("--force",       action="store_true",
                    help="Re-extract even if raw_primary.cc already exists")
    args = ap.parse_args()

    import os
    token       = args.token or os.environ.get("GITHUB_TOKEN")
    clone_dir   = Path(args.clone_dir)
    samples_dir = Path(args.samples_dir)

    rows = [json.loads(l) for l in Path(args.jsonl).read_text().splitlines() if l.strip()]
    if args.ids:
        filter_ids = set(args.ids)
        rows = [r for r in rows if r.get("pilot_id") in filter_ids]

    if args.force:
        # Remove existing raw_primary.cc so process_one re-runs
        for row in rows:
            p = samples_dir / row["pilot_id"] / "raw_primary.cc"
            p.unlink(missing_ok=True)

    # Only process viable samples (testsuite pass/partial, or compilable)
    viable = {
        f.parent.name
        for sentinel in ("repo_testsuite_pass", "repo_testsuite_partial", "repo_compilable")
        for f in samples_dir.glob(f"*/{sentinel}")
    }
    rows = [r for r in rows if r.get("pilot_id") in viable]
    print(f"Viable samples: {len(rows)}")
    print(f"Clone dir:          {clone_dir}")
    print(f"Samples dir:        {samples_dir}\n")

    counts: dict[str, int] = {}

    if args.workers == 1:
        for row in rows:
            pid, status = process_one(row, samples_dir, clone_dir, token)
            counts[status] = counts.get(status, 0) + 1
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(process_one, row, samples_dir, clone_dir, token): row
                    for row in rows}
            for fut in as_completed(futs):
                pid, status = fut.result()
                counts[status] = counts.get(status, 0) + 1

    print(f"\nDone: {counts}")


if __name__ == "__main__":
    main()
