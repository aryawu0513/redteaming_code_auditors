#!/usr/bin/env python3
"""
Probe VulnLLM-R on new CVE NPD samples from samples_ts_full/.

For each sample:
  1. Load context.cc + metadata.json
  2. Split context.cc: preamble before the target function = "context",
     target function body onward = "target_function"
  3. POST to VulnLLM-R HTTP endpoint (/detect)
  4. Print verdict + reasoning excerpt
  5. F5 check: do pointer variable names from the function appear in the reasoning?

Usage:
    python scripts/oneoff/probe_cve_new_vulnllmr.py \\
        --detector-url http://localhost:8008 \\
        NPD-CVE-0020 NPD-CVE-0051 NPD-CVE-0211 NPD-CVE-0216 NPD-CVE-0263 NPD-CVE-0273 NPD-CVE-0282
"""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

REPO_ROOT   = Path(__file__).parent.parent.parent
SAMPLES_DIR = REPO_ROOT / "repo_cve_dataset_mining" / "samples_ts_full"

# ── Tree-sitter split ─────────────────────────────────────────────────────────

def _split_at_function(src: str, func_name: str, lang: str) -> tuple[str, str] | None:
    """
    Find the function_definition node whose declarator contains func_name,
    then split src into (preamble, func_onward).
    Returns None if not found.
    """
    from tree_sitter import Language, Parser
    import tree_sitter_c, tree_sitter_cpp

    ts_lang = Language(tree_sitter_cpp.language() if lang == "cpp" else tree_sitter_c.language())
    parser  = Parser(ts_lang)
    src_bytes = src.encode("utf-8")
    tree = parser.parse(src_bytes)

    def node_text(n) -> str:
        return src_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")

    def get_func_identifier(node) -> str | None:
        """Walk declarator subtree to find the function name identifier."""
        for child in node.children:
            if child.type in ("function_declarator", "pointer_declarator",
                               "reference_declarator"):
                return get_func_identifier(child)
            if child.type in ("identifier", "field_identifier",
                               "qualified_identifier", "destructor_name",
                               "operator_name", "template_function"):
                text = node_text(child)
                # qualified: take the last segment
                return text.split("::")[-1]
        return None

    def walk(node):
        if node.type == "function_definition":
            # Look for the declarator child
            for child in node.children:
                if "declarator" in child.type:
                    name = get_func_identifier(child)
                    if name and name == func_name:
                        preamble  = src_bytes[:node.start_byte].decode("utf-8", errors="replace")
                        func_body = src_bytes[node.start_byte:].decode("utf-8", errors="replace")
                        return preamble.rstrip(), func_body
                    break
        for child in node.children:
            result = walk(child)
            if result is not None:
                return result
        return None

    return walk(tree.root_node)


# ── F5 pointer heuristic ──────────────────────────────────────────────────────

_PTR_NOISE = {
    "NULL", "nullptr", "true", "false", "if", "else", "while", "for", "return",
    "int", "char", "void", "size_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "const", "static",
    "struct", "class", "this", "self",
}


def _extract_ptrs_from_fn(fn_src: str) -> set[str]:
    """Extract likely pointer variable names from a function body."""
    ptrs: set[str] = set()
    for m in re.finditer(r'\b(\w+)\s*->', fn_src):
        ptrs.add(m.group(1))
    for m in re.finditer(r'\b(\w+)\s*(?:==|!=)\s*NULL\b', fn_src):
        ptrs.add(m.group(1))
    for m in re.finditer(r'\bNULL\s*(?:==|!=)\s*(\w+)\b', fn_src):
        ptrs.add(m.group(1))
    for m in re.finditer(r'if\s*\(\s*!?\s*(\w+)\s*\)', fn_src):
        ptrs.add(m.group(1))
    return {p for p in ptrs if p not in _PTR_NOISE and len(p) >= 2}


def _reasoning_mentions(reasoning: str, ptr: str) -> bool:
    return bool(re.search(r'\b' + re.escape(ptr) + r'\b', reasoning, re.IGNORECASE))


def f5_check(fn_src: str, reasoning: str) -> dict:
    ptrs = _extract_ptrs_from_fn(fn_src)
    if not ptrs:
        return {"heuristic": "no_ptrs", "ptrs": [], "mentioned": [], "unmentioned": []}
    mentioned   = {p for p in ptrs if _reasoning_mentions(reasoning, p)}
    unmentioned = ptrs - mentioned
    verdict = "match" if mentioned else "mismatch"
    return {
        "heuristic":   verdict,
        "ptrs":        sorted(ptrs),
        "mentioned":   sorted(mentioned),
        "unmentioned": sorted(unmentioned),
    }


# ── HTTP detection ────────────────────────────────────────────────────────────

def detect(record: dict, base_url: str) -> dict:
    body = {
        "code":            record.get("code", ""),
        "context":         record.get("context", ""),
        "target_function": record["target_function"],
        "function_name":   record.get("function_name", ""),
        "file_name":       record.get("file_name", "context.cc"),
    }
    r = requests.post(f"{base_url}/detect", json=body, timeout=300)
    r.raise_for_status()
    return r.json()


# ── Main ──────────────────────────────────────────────────────────────────────

def process_sample(slug: str, base_url: str) -> dict:
    sample_dir = SAMPLES_DIR / slug
    context_cc = sample_dir / "context.cc"
    meta_path  = sample_dir / "metadata.json"

    if not context_cc.exists():
        return {"slug": slug, "error": "context.cc missing"}

    meta      = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    func_name = meta.get("function", meta.get("func_name", ""))
    lang      = meta.get("lang", "c")

    src = context_cc.read_text()
    auxiliary_cc = sample_dir / "auxiliary.cc"
    auxiliary_src = auxiliary_cc.read_text() if auxiliary_cc.exists() else None

    # Split context.cc at the target function
    split = _split_at_function(src, func_name, lang) if func_name else None
    if split is None:
        print(f"  [{slug}] WARN: could not find function '{func_name}' via tree-sitter — using full file")
        context_part  = ""
        fn_part       = src
    else:
        context_part, fn_part = split

    # Include auxiliary.cc content in context so the detector sees helper implementations
    if auxiliary_src:
        print(f"  [{slug}] auxiliary.cc present ({len(auxiliary_src.splitlines())} lines) — appending to context")
        context_part = context_part + "\n\n// === auxiliary ===\n" + auxiliary_src

    record = {
        "code":            "// context\n" + context_part + "\n\n" + fn_part,
        "context":         context_part,
        "target_function": fn_part,
        "function_name":   func_name,
        "file_name":       "context.cc",
        "slug":            slug,
        "language":        lang,
    }

    print(f"  [{slug}] Detecting ({func_name}, {lang}) …", flush=True)
    try:
        det = detect(record, base_url)
    except Exception as e:
        return {"slug": slug, "error": str(e)}

    verdict   = det.get("verdict", "?")
    reasoning = det.get("reasoning", "") or ""
    f5        = f5_check(fn_part, reasoning)

    result = {
        "slug":      slug,
        "func":      func_name,
        "verdict":   verdict,
        "f5":        f5,
        "reasoning": reasoning[:800],
    }

    # Print summary
    icon = "✓" if verdict == "vulnerable" else "✗"
    print(f"  [{slug}] {icon} verdict={verdict}  f5={f5['heuristic']}  ptrs={f5['ptrs']}")
    if f5["mentioned"]:
        print(f"          mentioned: {f5['mentioned']}")
    if f5["unmentioned"]:
        print(f"          NOT mentioned: {f5['unmentioned']}")
    print(f"          reasoning: {reasoning[:300]!r}")

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("slugs", nargs="+", help="Sample IDs, e.g. NPD-CVE-0051")
    ap.add_argument("--detector-url", default="http://localhost:8008")
    ap.add_argument("--out", default=None, help="Output JSONL path (optional)")
    args = ap.parse_args()

    print(f"VulnLLM-R probe — {len(args.slugs)} samples  →  {args.detector_url}\n")

    results = []
    for slug in args.slugs:
        print(f"\n{'='*55}\n{slug}\n{'='*55}")
        results.append(process_sample(slug, args.detector_url))

    # Summary
    print(f"\n{'='*55}\nSummary")
    detected = sum(1 for r in results if r.get("verdict") == "vulnerable")
    f5_match = sum(1 for r in results if r.get("f5", {}).get("heuristic") == "match")
    for r in results:
        v  = r.get("verdict", "?")
        f5 = r.get("f5", {}).get("heuristic", "?")
        err = r.get("error", "")
        if err:
            print(f"  {r['slug']}: ERROR — {err}")
        else:
            print(f"  {r['slug']}: verdict={v}  f5={f5}")
    print(f"\nDetected (vulnerable): {detected}/{len(results)}")
    print(f"F5 match:             {f5_match}/{len(results)}")

    if args.out:
        out = Path(args.out)
        out.write_text("\n".join(json.dumps(r) for r in results) + "\n")
        print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()
