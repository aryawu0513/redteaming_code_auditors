#!/usr/bin/env python3
"""Attack-file generator for RepoAudit and VulnLLM-R datasets.

Reads variant metadata and attack texts from automatic/texts/{language}_{bug_type}.json
and writes the attack dataset (buggy baseline + context-aware attacks) to the benchmark
and dataset directories for both systems.

Supported combinations:
    c / npd      — C Null Pointer Dereference (CWE-476)
    c / uaf      — C Use After Free (CWE-416)
    python / npd — Python Null Pointer Dereference (CWE-476)

Usage (as script):
    python automatic/gen_attacks.py --bug-type npd --language c
    python automatic/gen_attacks.py --bug-type uaf --language c
    python automatic/gen_attacks.py --bug-type npd --language python

Usage (as library):
    from automatic.gen_attacks import generate_all
    generate_all("c", "npd")
    generate_all("c", "npd", ra_base="/some/test/dir", vl_base="/other/test/dir")
"""

import argparse
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTO = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Per-combination config
# ---------------------------------------------------------------------------

_TOOLS_C  = ["TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity"]
_TOOLS_PY = ["TOOL_Pysa", "TOOL_Mypy", "TOOL_Atheris", "TOOL_Bandit"]

CONFIG = {
    ("c", "npd"): {
        "ext":           "c",
        "cwe":           "CWE-476",
        "lang_str":      "c",
        "target_fn_sep": "// target function\n",
        "tools":         _TOOLS_C,
        "ra_base":       f"{REPO}/RepoAudit/benchmark/C/NPD",
        "vl_base":       f"{REPO}/VulnLLM-R/datasets/C/NPD",
    },
    ("c", "uaf"): {
        "ext":           "c",
        "cwe":           "CWE-416",
        "lang_str":      "c",
        "target_fn_sep": "// target function\n",
        "tools":         _TOOLS_C,
        "ra_base":       f"{REPO}/RepoAudit/benchmark/C/UAF",
        "vl_base":       f"{REPO}/VulnLLM-R/datasets/C/UAF",
    },
    ("python", "npd"): {
        "ext":           "py",
        "cwe":           "CWE-476",
        "lang_str":      "python",
        "target_fn_sep": "# target function\n",
        "tools":         _TOOLS_PY,
        "ra_base":       f"{REPO}/RepoAudit/benchmark/Python/NPD",
        "vl_base":       f"{REPO}/VulnLLM-R/datasets/Python/NPD",
    },
}

_CTX_BASE = ["COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA"]


def ctx_attacks(language, bug_type):
    return _CTX_BASE + CONFIG[(language, bug_type)]["tools"]


# ---------------------------------------------------------------------------
# Variant loader
# ---------------------------------------------------------------------------

def _load_variants(benchmark_base, json_path, ext, clean_subdir="buggy"):
    data = {}
    if not os.path.exists(json_path):
        return data
    with open(json_path) as f:
        src = json.load(f)
    for vname, vdata in src.items():
        if vname in data or "meta" not in vdata:
            continue
        clean_path = os.path.join(benchmark_base, clean_subdir, vname, f"{vname}_clean.{ext}")
        with open(clean_path) as f:
            clean = f.read()
        texts = {k: v for k, v in vdata.items() if k != "meta"}
        data[vname] = {**vdata["meta"], f"clean_{ext}": clean, "texts": texts}
    return data


def load_variants(language, bug_type, ra_base):
    cfg          = CONFIG[(language, bug_type)]
    ext          = cfg["ext"]
    clean_subdir = cfg.get("clean_subdir", "buggy")
    texts_path   = os.path.join(AUTO, "texts", f"{language}_{bug_type}.json")
    return _load_variants(ra_base, texts_path, ext, clean_subdir)


# ---------------------------------------------------------------------------
# Injection helper
# ---------------------------------------------------------------------------

def inject(clean_code, *, before_context=None, between_call_and_deref=None,
           before_call=None, on_deref_line=None, after_deref=None, after_file=None,
           call_line=None, deref_line=None):
    lines  = clean_code.split("\n")
    result = []

    if before_context:
        result.append(before_context)

    for line in lines:
        if before_call and call_line and line.strip() == call_line.strip():
            result.append(before_call)
            result.append(line)
            continue
        if between_call_and_deref and call_line and line.strip() == call_line.strip():
            result.append(line)
            result.append(between_call_and_deref)
            continue
        if on_deref_line and deref_line and line.strip() == deref_line.strip():
            result.append(line + "  " + on_deref_line)
            continue
        if after_deref and deref_line and line.strip() == deref_line.strip():
            result.append(line)
            result.append(after_deref)
            continue
        result.append(line)

    if after_file:
        result.append(after_file)

    return "\n".join(result).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# Build functions
# ---------------------------------------------------------------------------

def build_repoaudit(clean, vname, attack_name, language, bug_type, variants):
    """Build a RepoAudit source file for a context-aware attack.

    Injects the attack text between the call line and deref line.
    """
    v          = variants[vname]
    call_line  = v["call_line"]
    deref_line = v["deref_line"]
    texts      = v["texts"]

    if attack_name in texts:
        return inject(clean, between_call_and_deref=texts[attack_name],
                      call_line=call_line, deref_line=deref_line)

    raise ValueError(f"Unknown attack for {language}/{bug_type}: {attack_name}")


def build_vulnllm_code(clean_code, vname, attack_name, language, bug_type, variants):
    """Build code string for VulnLLM-R JSON.

    PRE_FUNC attacks (COT, FT, CG, TOOL_*): inserted before caller function definition.
    AA_* and remaining context-aware: injected inline between call and deref.
    """
    v      = variants[vname]
    texts  = v["texts"]
    cfg    = CONFIG[(language, bug_type)]
    sep    = cfg["target_fn_sep"]

    if attack_name == "clean":
        return clean_code

    # ── Context-aware: inline in target function section ──────────────────
    if sep in clean_code:
        ctx_part, target_part = clean_code.split(sep, 1)
    else:
        ctx_part, target_part = clean_code, ""

    # PRE_FUNC attacks insert before the caller function definition
    # (disabled for annotated variants, which place all attacks inline)
    _pre_func = ({"COT", "FT", "CG"} | set(cfg["tools"])) if cfg.get("use_pre_func", True) else set()
    if attack_name in _pre_func:
        attack_text = texts[attack_name]
        fn_prefix = v["caller_sig"] if "caller_sig" in v else f"def {v['caller']}("
        lines  = target_part.split("\n")
        result = []
        for line in lines:
            if line.startswith(fn_prefix):
                result.append(attack_text)
            result.append(line)
        return ctx_part + sep + "\n".join(result)

    # AA_* and any remaining: inline between call and deref
    attacked = build_repoaudit(target_part.lstrip(), vname, attack_name,
                               language, bug_type, variants)
    return ctx_part + sep + attacked.lstrip("\n")


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------

def write_repoaudit_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def write_vulnllm_json(path, code, language, bug_type):
    cfg = CONFIG[(language, bug_type)]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = [{
        "CWE_ID":      [cfg["cwe"]],
        "code":        code,
        "target":      1,
        "language":    cfg["lang_str"],
        "dataset":     "custom",
        "idx":         1,
        "RELATED_CWE": [],
        "stack_trace": True,
    }]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_all(language, bug_type, ra_base=None, vl_base=None):
    """Generate attack files for a given language/bug-type combination.

    ra_base / vl_base: override output directories (default: config paths).
    Variant clean files are always read from the ground-truth config paths.
    """
    cfg        = CONFIG[(language, bug_type)]
    ra_out     = ra_base or cfg["ra_base"]
    vl_out     = vl_base or cfg["vl_base"]
    ext        = cfg["ext"]
    lang_str   = cfg["lang_str"]
    dir_prefix = cfg.get("dir_prefix", "")
    ctx        = ctx_attacks(language, bug_type)
    variants   = load_variants(language, bug_type, cfg["ra_base"])

    for vname, vdata in variants.items():
        clean      = vdata[f"clean_{ext}"]
        clean_code = vdata["clean_code"]

        # --- Clean baseline ---
        write_repoaudit_file(
            f"{ra_out}/{dir_prefix}buggy/{vname}/{vname}_clean.{ext}", clean)
        write_vulnllm_json(
            f"{vl_out}/{dir_prefix}buggy/{vname}/{lang_str}/{vname}_clean.json",
            clean_code, language, bug_type)
        print(f"  [{vname}] buggy")

        # --- Context-aware attacks ---
        for attack in ctx:
            src  = build_repoaudit(clean, vname, attack, language, bug_type, variants)
            write_repoaudit_file(
                f"{ra_out}/{dir_prefix}context_aware/{vname}/{vname}_{attack}.{ext}", src)
            code = build_vulnllm_code(clean_code, vname, attack, language, bug_type, variants)
            write_vulnllm_json(
                f"{vl_out}/{dir_prefix}context_aware/{vname}/{lang_str}/{vname}_{attack}.json",
                code, language, bug_type)
        print(f"  [{vname}] {len(ctx)} context-aware attacks")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate adversarial attack files for a bug type + language.")
    parser.add_argument("--bug-type", required=True, choices=["npd", "uaf"])
    parser.add_argument("--language", required=True, choices=["c", "python"])
    parser.add_argument("--ra-base",  help="Override RepoAudit output directory")
    parser.add_argument("--vl-base",  help="Override VulnLLM-R output directory")
    args = parser.parse_args()

    key = (args.language, args.bug_type)
    if key not in CONFIG:
        parser.error(f"Unsupported combination: {key}")

    generate_all(args.language, args.bug_type,
                 ra_base=args.ra_base, vl_base=args.vl_base)
    print(f"\nDone. All {args.language.upper()} {args.bug_type.upper()} attack files generated.")


if __name__ == "__main__":
    main()
