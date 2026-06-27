"""
Classify 128 CVE NPD bugs along independent static-analysis precision axes.

Each bug gets a feature vector rather than a single primary category.
The axes map directly to well-established SA precision dimensions:

  source_kind      — what produces the null (observable in function body)
    null_literal   : explicit `ptr = NULL` in body, then dereferenced
    stdlib_alloc   : malloc/calloc/realloc return unchecked
    stdlib_other   : stdlib fn that may return null (fopen, strstr, getenv…)
    output_param   : null initialized then passed via &ptr to a callee
    callee_return  : user-defined function return used as pointer
    struct_field   : pointer read from struct field (obj->field)
    param_in       : pointer parameter, null at call sites
    unknown        : no null source visible in primary_file

  source_locality  — where the null originates relative to the function
    in_function    : null assigned inside the target function body
                     (null_literal, stdlib_alloc, stdlib_other, output_param)
    cross_function : null comes from outside the function but within the file
                     (callee_return where callee defined in same file,
                      struct_field set externally, param_in from caller)
    cross_file     : null source not visible in primary_file at all

  requires_interprocedural — bool
    True if resolving the null source requires analyzing caller/callee
    relationships (cross_function or cross_file locality, or callee_return)

  requires_field_sensitivity — bool
    True if a struct field dereference is involved

References:
  Livshits et al., "In Defense of Soundiness" (CACM 2015) — precision dimensions
  Calcagno et al., "Compositional Shape Analysis" (POPL 2011) — interprocedural
  Márton & Krupp, "What Every C Programmer Should Know About CTU" (ICSE 2020)
  Tomassi et al., "Real-World Effectiveness of Static Bug Detectors" (ASE 2021)
  Habib & Pradel, "How Many of All Bugs Do We Find?" (ASE 2018)

Output: results/npd_classification.json + prints a table.
"""

import json
import re
from pathlib import Path
from collections import Counter

ROOT       = Path(__file__).parent.parent.parent
BENCH_ROOT = ROOT / "benchmark/cvebench_full/baseline"

# Manual overrides for samples where the regex cannot determine source_kind.
# Reasons documented below each entry:
#   NPD-CVE-0377 / 0378: `current_buf = YY_CURRENT_BUFFER` is a macro expansion;
#     no `=` assignment visible in source — struct_field via macro.
#   NPD-CVE-0585: `line_context` is a pointer param on a continuation line of the
#     signature; single-line sig parser misses it — param_in.
#   NPD-CVE-0678: C++ constructor initializer list; `pLoader = _glyph_loader` is a
#     member field, not a function call — struct_field via member.
MANUAL_OVERRIDES: dict[str, str] = {
    "NPD-CVE-0377": "struct_field",
    "NPD-CVE-0378": "struct_field",
    "NPD-CVE-0585": "param_in",
    "NPD-CVE-0678": "struct_field",
}

STDLIB_NULL_FUNCS = re.compile(
    r'\b(fopen|fclose|fdopen|freopen|popen|tmpfile|'
    r'strstr|strchr|strrchr|strpbrk|strdup|strndup|'
    r'getenv|secure_getenv|getline|getdelim|'
    r'strtok|strtok_r|strtok_s|'
    r'opendir|readdir|fdopendir|'
    r'realpath|canonicalize_file_name|'
    r'regcomp|inet_ntoa|inet_ntop|'
    r'dlopen|dlsym|mmap|getcwd|getwd)\s*\('
)

# malloc wrappers commonly used in C projects (macros or thin wrappers)
CUSTOM_ALLOC = re.compile(
    r'\b(malloc|calloc|realloc|'
    r're_yyalloc|yyalloc|'           # flex-generated allocators
    r'CPU_ALLOC|'                    # hwloc / glibc macro
    r'jas_alloc2?|jas_matrix_create|' # jasper
    r'g_malloc|g_new|g_new0|'       # glib
    r'xmalloc|xzalloc|xcalloc|'     # common project wrappers
    r'zmalloc|zalloc)\s*\('
)
STDLIB_ALLOC = CUSTOM_ALLOC  # kept as alias for existing references

# Detectability tier per source_kind, grounded in tool capabilities
DETECTABILITY = {
    "null_literal":   "HIGH",    # intra-procedural flow-sensitive
    "stdlib_alloc":   "HIGH",    # stdlib alloc model (CppCheck, Clang SA, Infer)
    "stdlib_other":   "MEDIUM",  # stdlib null model (CppCheck, Clang SA configurable)
    "callee_return":  "MEDIUM",  # interprocedural summary (Infer biabduction, CodeQL)
    "output_param":   "LOW",     # output-parameter modeling
    "struct_field":   "LOW",     # field-sensitive heap analysis
    "param_in":       "LOW",     # backward call-site enumeration
    "unknown":        "VERY_LOW", # requires CTU analysis (Clang SA CTU, CodeQL whole-program)
}


def find_function_range(source: str, fn: str):
    lines = source.splitlines()
    start = depth = None
    seen_open = False
    for i, line in enumerate(lines, 1):
        if start is None and re.search(rf'\b{re.escape(fn)}\s*\(', line):
            start = i
        if start is not None:
            depth += line.count('{') - line.count('}') if depth is not None else (
                line.count('{') - line.count('}'))
            if depth is None:
                depth = line.count('{') - line.count('}')
            if depth > 0:
                seen_open = True
            if seen_open and depth <= 0:
                return start, i
    return (start or 1), len(lines)


def get_func_body(source: str, fn: str):
    """Return (sig_line, body) for the DEFINITION of fn, skipping forward declarations."""
    lines = source.splitlines()
    start = depth = None
    seen_open = False
    sig_line = ""
    for i, line in enumerate(lines):
        if start is None and re.search(rf'\b{re.escape(fn)}\s*\(', line):
            # Skip forward declarations: scan forward until '{' or ';'
            scan = line
            j = i
            found_open = '{' in scan and (';' not in scan or scan.index('{') < scan.index(';'))
            while not found_open and ';' not in scan and j < len(lines) - 1:
                j += 1
                scan = lines[j]
                found_open = '{' in scan
            if not found_open:
                continue
            start = i
            sig_line = line
        if start is not None:
            depth = (depth or 0) + line.count('{') - line.count('}')
            if depth > 0:
                seen_open = True
            if seen_open and depth <= 0:
                return sig_line, "\n".join(lines[start:i+1])
    if start is not None:
        return sig_line, "\n".join(lines[start:])
    return "", ""


def _scan_kinds(body: str, sig: str, stdlib_only: bool = False) -> list[str]:
    """Extract source_kind signals from a code block."""
    kinds = []

    null_assigns = re.findall(r'\b(\w+)\s*=\s*NULL\s*;', body)
    for var in null_assigns:
        if re.search(rf'\b{re.escape(var)}\s*(?:->|\[)', body):
            kinds.append("null_literal")
            break

    if STDLIB_ALLOC.search(body):
        kinds.append("stdlib_alloc")

    if STDLIB_NULL_FUNCS.search(body):
        kinds.append("stdlib_other")

    if re.search(r'=\s*NULL\s*;', body) and re.search(r'&\w+\s*[,)]', body):
        kinds = [k for k in kinds if k != "null_literal"]
        if "output_param" not in kinds:
            kinds.append("output_param")

    if not stdlib_only:
        if re.search(r'=\s*(?:\([^)]+\)\s*)?\w+\s*->\s*\w+', body):
            kinds.append("struct_field")
        # struct_field via dot accessor: obj.field where field is a pointer (e.g. hwres.data[0])
        if re.search(r'\b\w+\.\w+\s*[\[\(]', body):
            kinds.append("struct_field")

        # callee_return: several patterns
        if not any(k in kinds for k in ("stdlib_alloc", "stdlib_other", "output_param")):
            cr = False
            # (a) pointer declaration: `Type *var = fn(`
            if re.search(r'\*\s*\w+\s*=\s*\w+\s*\(', body):
                cr = True
            if not cr:
                # (b) `var = fn(...)` where var is then dereferenced via var-> or var[
                _SKIP = {"NULL","malloc","calloc","realloc","sizeof","if","while","for","return"}
                for var, callee in re.findall(r'\b(\w+)\s*=\s*(\w+)\s*\(', body):
                    if callee in _SKIP or not var[0].isalpha():
                        continue
                    if re.search(rf'\b{re.escape(var)}\s*(?:->|\[)', body):
                        cr = True
                        break
            if not cr:
                # (c) `var = obj.method(` or `var = Cls::fn(` (C++ call syntax)
                for var in re.findall(r'\b(\w+)\s*=\s*\w+[\.:]+\w+\s*\(', body):
                    if re.search(rf'\b{re.escape(var)}\s*(?:->|\[|\*{re.escape(var)})', body) \
                            or re.search(rf'\*\s*{re.escape(var)}\b', body):
                        cr = True
                        break
            if not cr:
                # (d) `*var = alloc(...)` then `*var` dereferenced (e.g. *ptr_yy_globals)
                for var in re.findall(r'\*\s*(\w+)\s*=\s*\w+\s*\(', body):
                    if re.search(rf'\*\s*{re.escape(var)}\b', body):
                        cr = True
                        break
            if cr:
                kinds.append("callee_return")

        if sig:
            ptr_params = re.findall(r'\b\w[\w\s*]*\*+\s*(\w+)\s*[,)]', sig)
            # param_in: pointer param dereferenced via ->, *, or []
            if any(
                re.search(rf'\b{re.escape(p)}\s*(?:->|\[)', body) or
                re.search(rf'\*\s*(?:\([^)]*\)\s*)?\b{re.escape(p)}\b', body)
                for p in ptr_params if p
            ):
                kinds.append("param_in")

    return kinds


def classify(slug: str, fn: str, primary: str, auxiliary: str = "") -> dict:
    sig, body = get_func_body(primary, fn)
    if not body:
        body = primary

    # Scan primary file for all kinds
    kinds = _scan_kinds(body, sig)

    # Scan auxiliary file: adds callee_return / struct_field signals not visible
    # in the function body itself.
    # stdlib_alloc is intentionally excluded: if a callee in aux does malloc and
    # returns the pointer, the correct kind is callee_return, not stdlib_alloc.
    if auxiliary:
        aux_kinds = _scan_kinds(auxiliary, sig="")
        for k in aux_kinds:
            if k not in kinds and k != "stdlib_alloc":
                kinds.append(k)

    if not kinds:
        kinds.append("unknown")

    priority = ["null_literal", "stdlib_alloc", "stdlib_other", "output_param",
                "callee_return", "struct_field", "param_in", "unknown"]
    primary_kind = next((k for k in priority if k in kinds), "unknown")

    # Apply manual override when regex cannot determine source_kind
    manual = MANUAL_OVERRIDES.get(slug)
    if manual and primary_kind == "unknown":
        primary_kind = manual
        if manual not in kinds:
            kinds.append(manual)
        kinds = [k for k in kinds if k != "unknown"]

    # --- source_locality ---
    if primary_kind in ("null_literal", "stdlib_alloc", "stdlib_other", "output_param"):
        locality = "in_function"
    elif primary_kind == "callee_return":
        callee_calls = re.findall(r'\*\s*\w+\s*=\s*(\w+)\s*\(', body)
        # callee defined in primary file → cross_function; in aux → cross_file
        in_primary = any(
            re.search(rf'^\s*(?:\w[\w\s*:]+\s+)?{re.escape(c)}\s*\(', primary, re.MULTILINE)
            for c in callee_calls if c not in ("malloc", "calloc", "realloc")
        )
        locality = "cross_function" if in_primary else "cross_file"
    elif primary_kind in ("struct_field", "param_in"):
        locality = "cross_function"
    else:
        locality = "cross_file"

    requires_interprocedural   = locality in ("cross_function", "cross_file")
    requires_field_sensitivity = "struct_field" in kinds

    return {
        "slug":                       slug,
        "function":                   fn,
        "source_kind":                primary_kind,
        "all_kinds":                  kinds,
        "source_locality":            locality,
        "requires_interprocedural":   requires_interprocedural,
        "requires_field_sensitivity": requires_field_sensitivity,
        "sa_detectability":           DETECTABILITY[primary_kind],
    }


def main():
    samples = []
    for d in sorted(BENCH_ROOT.iterdir()):
        for f in sorted(d.iterdir()):
            if f.name.endswith("_CLEAN.json"):
                samples.append(json.loads(f.read_text())[0])

    results = [classify(s["slug"], s["function_name"],
                        s["primary_file"], s.get("auxiliary_file") or "")
               for s in samples]

    out = Path(__file__).parent / "npd_classification.json"
    out.write_text(json.dumps(results, indent=2))

    n = len(results)

    # --- source_kind table ---
    kind_counts = Counter(r["source_kind"] for r in results)
    print(f"\n{'='*72}")
    print(f"NPD Feature-Vector Classification — {n} samples")
    print(f"{'='*72}")
    print(f"\n{'source_kind':20s}  {'N':>5}  {'%':>6}  {'detectability':14s}  (analysis needed)")
    print("-" * 80)
    desc = {
        "null_literal":  "intra-procedural, flow-sensitive",
        "stdlib_alloc":  "stdlib alloc model",
        "stdlib_other":  "stdlib null model (configurable)",
        "output_param":  "output-parameter modeling",
        "callee_return": "interprocedural summary",
        "struct_field":  "field-sensitive heap analysis",
        "param_in":      "backward call-site enumeration",
        "unknown":       "cross-TU (CTU) analysis",
    }
    for kind in ["null_literal", "stdlib_alloc", "stdlib_other", "output_param",
                 "callee_return", "struct_field", "param_in", "unknown"]:
        nc = kind_counts.get(kind, 0)
        print(f"  {kind:20s}  {nc:5d}  {100*nc/n:5.1f}%  {DETECTABILITY[kind]:14s}  {desc[kind]}")

    # --- source_locality ---
    loc_counts = Counter(r["source_locality"] for r in results)
    print(f"\n{'source_locality':25s}  N")
    print("-" * 40)
    for loc in ["in_function", "cross_function", "cross_file"]:
        print(f"  {loc:25s}  {loc_counts.get(loc,0):3d}  ({100*loc_counts.get(loc,0)/n:.1f}%)")

    # --- derived flags ---
    ip  = sum(1 for r in results if r["requires_interprocedural"])
    fs  = sum(1 for r in results if r["requires_field_sensitivity"])
    print(f"\nrequires_interprocedural:   {ip}/{n}  ({100*ip/n:.1f}%)")
    print(f"requires_field_sensitivity: {fs}/{n}  ({100*fs/n:.1f}%)")

    # --- detectability summary ---
    det_counts = Counter(r["sa_detectability"] for r in results)
    print(f"\n{'SA detectability':20s}  N")
    print("-" * 35)
    for lvl in ["HIGH", "MEDIUM", "LOW", "VERY_LOW"]:
        nc = det_counts.get(lvl, 0)
        print(f"  {lvl:16s}  {nc:3d} / {n}  ({100*nc/n:.1f}%)")

    print(f"\nResults → {out}")


if __name__ == "__main__":
    main()
