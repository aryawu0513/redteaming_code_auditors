#!/usr/bin/env python3
"""
splice_target.py — replace a function definition in a real source file with a
new (attacker-generated) version, preserving all surrounding repo context.

Useful if evaluate whole-file / whole-repo detectors on our benchmark: the
benchmark's vulnerable target_function uses real project APIs, so dropping it
in place of the original function gives the detector the exact function-under-
test plus authentic cross-file context (type/API definitions elsewhere in the
repo).

No macro preprocessing — the file is preserved byte-for-byte except the spliced
function span.
"""
from __future__ import annotations

from tree_sitter import Language, Node, Parser
import tree_sitter_c
import tree_sitter_cpp

_LANG_C = Language(tree_sitter_c.language())
_LANG_CPP = Language(tree_sitter_cpp.language())


def _parser(lang: str) -> Parser:
    return Parser(_LANG_CPP if lang == "cpp" else _LANG_C)


def _fn_name(decl: Node, src: bytes) -> str | None:
    if decl is None:
        return None
    if decl.type == "function_declarator":
        return _fn_name(decl.child_by_field_name("declarator"), src)
    if decl.type in ("identifier", "field_identifier", "type_identifier"):
        return src[decl.start_byte:decl.end_byte].decode("utf-8", "replace")
    if decl.type in ("pointer_declarator", "reference_declarator"):
        return _fn_name(decl.child_by_field_name("declarator"), src)
    if decl.type == "qualified_identifier":
        return _fn_name(decl.child_by_field_name("name"), src)
    return None


def find_function_spans(file_text: str, func_name: str, lang: str = "cpp") -> list[tuple[int, int]]:
    """Return [(start_byte, end_byte)] of every function_definition named func_name."""
    src = file_text.encode("utf-8", "replace")
    tree = _parser(lang).parse(src)
    spans: list[tuple[int, int]] = []

    def visit(node: Node) -> None:
        if node.type == "function_definition":
            name = _fn_name(node.child_by_field_name("declarator"), src)
            if name == func_name:
                spans.append((node.start_byte, node.end_byte))
        for c in node.children:
            visit(c)

    visit(tree.root_node)
    return spans


def splice_function(file_text: str, func_name: str, new_func: str,
                    lang: str = "cpp") -> tuple[str, int]:
    """
    Replace the body+signature of every definition of func_name with new_func.
    Returns (new_file_text, n_replaced). n_replaced == 0 means the function
    was not found (caller should treat as a splice failure).
    """
    src = file_text.encode("utf-8", "replace")
    spans = find_function_spans(file_text, func_name, lang)
    if not spans:
        return file_text, 0
    # Replace right-to-left so earlier byte offsets stay valid.
    new_bytes = new_func.encode("utf-8", "replace")
    out = src
    for start, end in sorted(spans, reverse=True):
        out = out[:start] + new_bytes + out[end:]
    return out.decode("utf-8", "replace"), len(spans)


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("file"); ap.add_argument("func"); ap.add_argument("newfunc_file")
    ap.add_argument("--lang", default="cpp")
    a = ap.parse_args()
    txt = open(a.file).read()
    nf = open(a.newfunc_file).read()
    spliced, n = splice_function(txt, a.func, nf, a.lang)
    print(f"replaced {n} definition(s) of {a.func}")
    print(spliced)
