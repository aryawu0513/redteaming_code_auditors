#!/usr/bin/env python3
"""
Tree-sitter-based extraction of a target function and its context from a
real source file fetched from GitHub.

Replaces the LLM-only extraction in build_harness_cve.py.  The LLM is still
used afterward — but only for the narrow task of inlining types and replacing
project #includes with standard-library includes.  All function body selection
is done deterministically here.

Public API
----------
extract_from_repo(row, token=None) -> str | None
    row: a dict with keys repo_url, commit_hash, file, function, lang
    token: optional GitHub token for rate-limit headroom
    Returns the raw extracted code (real function bodies, no stubs),
    ready to be passed to the LLM for portability cleanup.
"""

from __future__ import annotations

import re
import urllib.request
import urllib.error
from collections import deque
from pathlib import Path
from typing import Iterator, Sequence

from tree_sitter import Language, Node, Parser
import tree_sitter_c
import tree_sitter_cpp

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

_LANG_C   = Language(tree_sitter_c.language())
_LANG_CPP = Language(tree_sitter_cpp.language())


def _make_parser(lang: str) -> Parser:
    return Parser(_LANG_CPP if lang == "cpp" else _LANG_C)


# ---------------------------------------------------------------------------
# GitHub fetch
# ---------------------------------------------------------------------------

def _raw_url(repo_url: str, commit: str, file_path: str) -> str:
    """Convert a github.com repo URL to a raw.githubusercontent.com URL."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)", repo_url)
    if not m:
        raise ValueError(f"Cannot parse repo URL: {repo_url}")
    return f"https://raw.githubusercontent.com/{m.group(1)}/{commit}/{file_path}"


def fetch_source(repo_url: str, commit: str, file_path: str,
                 token: str | None = None) -> str:
    url = _raw_url(repo_url, commit, file_path)
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
    """Recursively unwrap a declarator to find the function name identifier."""
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
        # C++ qualified name like A::B::method — unwrap to rightmost identifier
        name = decl.child_by_field_name("name")
        result = _fn_name_from_declarator(name, src)
        if result:
            return result
        # name itself may be another qualified_identifier — keep unwrapping
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
    """Collect all direct call identifiers in node (non-recursive over fn defs)."""
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
                    # obj.method or obj->method — add method name
                    field = fn_node.child_by_field_name("field")
                    if field:
                        result.add(src[field.start_byte:field.end_byte].decode())
        # Don't recurse into nested function definitions
        if n.type != "function_definition":
            stack.extend(n.children)
    return result


def _collect_free_calls(node: Node, src: bytes) -> set[str]:
    """
    Like _collect_calls but only returns free function calls — i.e., calls
    where the callee is a plain identifier or qualified name, NOT a method
    call via '.' or '->'.  Used for cross-file resolution where method names
    are too ambiguous (we don't know the runtime type of the receiver).
    """
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
    """All identifiers appearing anywhere in node (for type dependency tracking)."""
    result: set[str] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("identifier", "type_identifier", "field_identifier"):
            result.add(src[n.start_byte:n.end_byte].decode())
        stack.extend(n.children)
    return result


# ---------------------------------------------------------------------------
# Top-level item catalog
# ---------------------------------------------------------------------------

class _Item:
    __slots__ = ("kind", "name", "node", "src_text")

    def __init__(self, kind: str, name: str, node: Node, src: bytes,
                 src_text_override: str | None = None):
        self.kind = kind          # "fn", "type", "macro", "include", "other"
        self.name = name
        self.node = node
        self.src_text = src_text_override if src_text_override is not None \
                        else _text(node, src)


def _strip_method_bodies(node: Node, src: bytes) -> str:
    """
    Return a class/struct declaration with all method bodies replaced by ';'.
    Member variable declarations and method signatures are kept.
    """
    raw = _text(node, src)
    result_parts: list[str] = []
    pos = node.start_byte

    def _process_field_list(flist: Node) -> None:
        nonlocal pos
        for child in flist.children:
            if child.type == "function_definition":
                # Emit everything up to the opening brace as signature
                body = child.child_by_field_name("body")
                if body:
                    sig_end = body.start_byte
                    result_parts.append(src[pos:sig_end].decode("utf-8", errors="replace"))
                    result_parts.append(";")
                    pos = child.end_byte
                # else: no body — leave as-is
            elif child.type in ("class_specifier", "struct_specifier"):
                # Recurse
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
    """Catalog all top-level items, including methods inside class bodies."""
    items: list[_Item] = []

    def _visit(node: Node, depth: int = 0) -> None:
        t = node.type
        if t == "function_definition":
            # Tree-sitter sometimes mis-parses class/struct/namespace definitions
            # as function_definitions when it hits a parse error (e.g. base-class
            # list). The keyword ('namespace', 'class', 'struct') ends up as the
            # return-type identifier. Detect this and recurse into the body so
            # we reach the actual function definitions inside.
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
            # Don't recurse into function bodies
            return
        if t in ("preproc_def", "preproc_function_def"):
            name_node = node.child_by_field_name("name")
            name = _text(name_node, src) if name_node else ""
            items.append(_Item("macro", name, node, src))
            return
        if t == "preproc_include":
            items.append(_Item("include", "", node, src))
            return
        if t in ("type_definition", "struct_specifier", "union_specifier",
                 "enum_specifier"):
            name = ""
            for child in node.children:
                if child.type in ("type_identifier", "identifier"):
                    name = _text(child, src)
                    break
            # Strip method bodies — individual methods are cataloged as "fn" items
            stripped = _strip_method_bodies(node, src)
            items.append(_Item("type", name, node, src, stripped))
            # Recurse into field list exactly like class_specifier so nested
            # functions (e.g. inside namespace cv { struct Foo { method... } })
            # are cataloged at arbitrary depth.
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
            # Strip method bodies — individual methods cataloged separately
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
            # Recurse into namespace bodies
            for child in node.children:
                if child.type == "declaration_list":
                    for gc in child.children:
                        _visit(gc, depth + 1)
            return
        if t == "comment":
            return
        if depth == 0:
            items.append(_Item("other", "", node, src))

    for child in tree_root.children:
        _visit(child, depth=0)

    return items


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------

def _project_include_paths(items: list["_Item"], primary_file: str) -> list[str]:
    """
    Return candidate file paths to search for unresolved callees, in priority order:
      1. The header counterpart of the primary file (.cc/.cpp/.c → .h)
      2. Each project (quoted) #include path found in the primary file
    Paths are repo-relative best-guesses; callers should try them and skip 404s.
    """
    candidates: list[str] = []

    # Header counterpart
    for ext, hdr in [(".cc", ".h"), (".cpp", ".h"), (".c", ".h")]:
        if primary_file.endswith(ext):
            candidates.append(primary_file[: -len(ext)] + hdr)
            break

    # Quoted includes from the file
    primary_dir = str(Path(primary_file).parent)
    for item in items:
        if item.kind != "include":
            continue
        m = re.search(r'#\s*include\s+"([^"]+)"', item.src_text)
        if not m:
            continue
        inc = m.group(1)
        # Try as repo-root-relative path, then relative to the primary file's dir
        for path in (inc, str(Path(primary_dir) / inc)):
            if path not in candidates:
                candidates.append(path)
            # Also try the .c / .cc sibling of any .h — function bodies live there
            for h_ext, impl_ext in ((".h", ".c"), (".h", ".cc"), (".hpp", ".cpp")):
                if path.endswith(h_ext):
                    impl = path[: -len(h_ext)] + impl_ext
                    if impl not in candidates:
                        candidates.append(impl)

    return candidates


def _fetch_and_extract(
    repo_url: str,
    commit: str,
    file_path: str,
    needed: set[str],
    parser: "Parser",
    token: str | None,
) -> tuple[list["_Item"], set[str]]:
    """
    Fetch file_path and return (items_found, resolved_names) where items_found
    contains _Items for any function in `needed` that is defined in that file,
    plus their transitive same-file callees.
    """
    try:
        raw = fetch_source(repo_url, commit, file_path, token)
    except Exception:
        return [], set()

    src = raw.encode("utf-8", errors="replace")
    tree = parser.parse(src)
    extra_items = _catalog(tree.root_node, src)
    extra_fn_by_name = {it.name: it for it in extra_items if it.kind == "fn"}

    found = needed & extra_fn_by_name.keys()
    if not found:
        return [], set()

    # Expand transitively within the extra file
    all_needed: set[str] = set()
    for seed in found:
        all_needed |= _transitive_callees(seed, extra_fn_by_name, src)
    all_needed &= extra_fn_by_name.keys()

    result_items = [it for it in extra_items if it.kind == "fn" and it.name in all_needed]
    # Also pull type/macro/include items from the extra file (LLM will clean up)
    result_items += [it for it in extra_items if it.kind in ("type", "macro", "include")]
    return result_items, found


def _fetch_quoted_includes(repo_url: str, commit: str, path: str,
                           token: str | None) -> list[str]:
    """Fetch a file and return its quoted #include paths (not angle-bracket ones)."""
    try:
        raw = fetch_source(repo_url, commit, path, token)
    except Exception:
        return []
    return re.findall(r'#\s*include\s+"([^"]+)"', raw)


def _resolve_cross_file_callees(
    unresolved: set[str],
    items: list["_Item"],
    fn_by_name: dict[str, "_Item"],
    repo_url: str,
    commit: str,
    primary_file: str,
    parser: "Parser",
    token: str | None,
    extra_files: Sequence[str] = (),
) -> tuple[list["_Item"], set[str]]:
    """
    For each unresolved callee name, search for its definition by trying:
      1. Any paths in extra_files (explicit overrides)
      2. The header counterpart of the primary file (.cc/.c → .h)
      3. Each project #include listed in the primary file
      4. Transitive: for each .h candidate fetched above, also try the quoted
         includes found inside that header (and their .c/.cc siblings).

    Returns (new_items, newly_resolved_names).
    """
    remaining = set(unresolved)
    new_items: list["_Item"] = []
    resolved: set[str] = set()

    # Queue of candidate paths to try; seeded with explicit + direct includes.
    candidate_paths = list(extra_files) + _project_include_paths(items, primary_file)
    seen_paths: set[str] = set()

    while candidate_paths and remaining:
        path = candidate_paths.pop(0)
        if path in seen_paths:
            continue
        seen_paths.add(path)

        found_items, found_names = _fetch_and_extract(
            repo_url, commit, path, remaining, parser, token
        )
        if found_names:
            print(f"    cross-file: {path} → {sorted(found_names)}")
            new_items.extend(found_items)
            resolved |= found_names
            remaining -= found_names

        # If this was a header, expand one level: parse its quoted includes and
        # add their .c/.cc siblings as new candidates so we reach implementation
        # files that aren't directly included by the primary source file.
        if path.endswith(".h") or path.endswith(".hpp"):
            primary_dir = str(Path(primary_file).parent)
            for inc in _fetch_quoted_includes(repo_url, commit, path, token):
                for base in (inc, str(Path(primary_dir) / inc)):
                    if base not in seen_paths:
                        candidate_paths.append(base)
                    for h_ext, impl_ext in ((".h", ".c"), (".h", ".cc"),
                                            (".hpp", ".cpp")):
                        if base.endswith(h_ext):
                            impl = base[: -len(h_ext)] + impl_ext
                            if impl not in seen_paths:
                                candidate_paths.append(impl)

    return new_items, resolved


def _unresolved_callees(fn_names: set[str], fn_by_name: dict[str, "_Item"],
                        src: bytes) -> set[str]:
    """
    Free function calls made from fn_names that are not defined in fn_by_name.
    Uses only free calls (not method calls) to avoid false positives when
    searching other files for definitions.
    """
    unresolved: set[str] = set()
    for name in fn_names:
        item = fn_by_name.get(name)
        if item is None:
            continue
        for callee in _collect_free_calls(item.node, src):
            if callee not in fn_by_name:
                unresolved.add(callee)
    return unresolved


def _transitive_callees(
    start_name: str,
    fn_by_name: dict[str, _Item],
    src: bytes,
) -> set[str]:
    """BFS over same-file callees starting from start_name."""
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


def _find_callers(target: str, fn_by_name: dict[str, _Item], src: bytes) -> set[str]:
    """Functions in the same file that directly call target."""
    result: set[str] = set()
    for name, item in fn_by_name.items():
        if name == target:
            continue
        if target in _collect_calls(item.node, src):
            result.add(name)
    return result


def _needed_type_names(fn_names: set[str], fn_by_name: dict[str, _Item],
                       src: bytes) -> set[str]:
    """All identifiers referenced in the given functions (rough type dependency)."""
    ids: set[str] = set()
    for name in fn_names:
        item = fn_by_name.get(name)
        if item:
            ids.update(_collect_identifiers(item.node, src))
    return ids


def _assemble_auxiliary(fn_names: set[str], items: list[_Item]) -> str:
    """
    Assemble auxiliary items (from multiple source files) using stored src_text
    only — no identifier-based filtering since nodes belong to different src bytes.
    Includes everything: all includes, macros, types, and functions in fn_names.
    """
    parts: list[str] = []
    for item in items:
        if item.kind in ("include", "macro", "type"):
            parts.append(item.src_text)
        elif item.kind == "fn" and item.name in fn_names:
            parts.append(item.src_text)
    return "\n\n".join(p.strip() for p in parts if p.strip())


def _assemble(
    fn_names: set[str],
    items: list[_Item],
    src: bytes,
    target_name: str,
) -> str:
    """
    Emit items in source order, keeping:
      - includes (caller decides whether to strip)
      - macros (all — small and usually needed)
      - types that share identifiers with any included function
      - functions in fn_names
    """
    fn_by_name = {it.name: it for it in items if it.kind == "fn"}
    needed_ids = _needed_type_names(fn_names, fn_by_name, src)

    parts: list[str] = []
    for item in items:
        if item.kind == "include":
            parts.append(item.src_text)
        elif item.kind == "macro":
            parts.append(item.src_text)
        elif item.kind == "type":
            # Include if the type name or any identifier in it overlaps
            type_ids = _collect_identifiers(item.node, src)
            if item.name in needed_ids or type_ids & needed_ids:
                parts.append(item.src_text)
        elif item.kind == "fn" and item.name in fn_names:
            parts.append(item.src_text)
        # "other" items (extern declarations, etc.) — include if they share ids
        elif item.kind == "other":
            other_ids = _collect_identifiers(item.node, src)
            if other_ids & needed_ids:
                parts.append(item.src_text)

    return "\n\n".join(p.strip() for p in parts if p.strip())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_from_repo(
    row: dict,
    token: str | None = None,
    include_callers: bool = True,
    split_auxiliary: bool = False,
) -> "str | tuple[str, str | None] | None":
    """
    Fetch the real source file and extract the target function plus all
    same-file callees (transitively) and, optionally, immediate callers.

    Cross-file callees are discovered automatically by following project
    #include paths and the header counterpart of the primary file.  Extra
    files may also be listed explicitly in row["extra_files"].

    Parameters
    ----------
    split_auxiliary : bool
        If False (default), return a single merged string.
        If True, return (primary_str, auxiliary_str | None) where primary
        contains only same-file content and auxiliary contains cross-file
        callee bodies — suitable for generating context.cc + auxiliary.cc.

    Returns None on failure.
    """
    repo_url   = row.get("repo_url", "")
    commit     = row.get("commit_hash", "")
    file_path  = row.get("file", row.get("file_path", ""))
    func_name  = row.get("function", row.get("func_name", ""))
    lang       = row.get("lang", "c")
    extra_files: list[str] = row.get("extra_files", [])

    if not (repo_url and commit and file_path and func_name):
        return None

    try:
        raw = fetch_source(repo_url, commit, file_path, token)
    except Exception as e:
        print(f"    fetch error: {e}")
        return None

    src    = raw.encode("utf-8", errors="replace")
    parser = _make_parser(lang)
    tree   = parser.parse(src)

    items      = _catalog(tree.root_node, src)
    fn_by_name = {it.name: it for it in items if it.kind == "fn"}

    if func_name not in fn_by_name:
        # Try suffix/substring match (handles Namespace::func_name in catalog keys)
        matches = [n for n in fn_by_name if n.endswith(func_name) or func_name in n]
        if matches:
            func_name = matches[0]
            print(f"    fuzzy match: using '{func_name}'")
        else:
            print(f"    '{func_name}' not found in {file_path} "
                  f"(found: {sorted(fn_by_name)[:8]})")
            return None

    callees = _transitive_callees(func_name, fn_by_name, src)
    callers: set[str] = set()
    if include_callers:
        callers = _find_callers(func_name, fn_by_name, src)

    fn_names = callees | callers

    # Resolve cross-file callees automatically via include-following
    unresolved = _unresolved_callees(fn_names, fn_by_name, src)
    cross_items: list[_Item] = []
    cross_fn_names: set[str] = set()
    if unresolved:
        cross_items, cross_fn_names = _resolve_cross_file_callees(
            unresolved, items, fn_by_name,
            repo_url, commit, file_path, parser, token,
            extra_files=extra_files,
        )

    if split_auxiliary:
        primary_str = _assemble(fn_names, items, src, func_name)
        auxiliary_str: str | None = None
        if cross_items and cross_fn_names:
            auxiliary_str = _assemble_auxiliary(cross_fn_names, cross_items)
        return (primary_str, auxiliary_str)

    # Merged mode (default)
    for it in cross_items:
        if it.kind == "fn" and it.name not in fn_by_name:
            fn_by_name[it.name] = it
            fn_names.add(it.name)
        items.append(it)
    return _assemble(fn_names, items, src, func_name)


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys, pathlib

    samples = pathlib.Path(__file__).parent / "samples_cve"

    for meta_path in sorted(samples.glob("*/metadata.json")):
        row = json.loads(meta_path.read_text())
        pid = row.get("pilot_id", meta_path.parent.name)
        print(f"\n{'='*60}")
        print(f"  {pid}  —  {row.get('function')}  ({row.get('file')})")
        result = extract_from_repo(row)
        if result is None:
            print("  FAILED")
        else:
            lines = result.splitlines()
            print(f"  {len(lines)} lines extracted")
            print("  --- first 20 lines ---")
            print("\n".join(lines[:20]))
