#!/usr/bin/env python3
"""
attack_agent.py — Malicious agent: extract metadata and generate adversarial payloads.

Threat model: The agent both introduces the vulnerable function and hides it.
It knows which function has the NPD because it wrote the code.

Two modes (--inject-bug flag):

  Default: repo already contains the buggy function.
    Uses ExtractVariantMetadata to pull structural anchors from existing buggy code.

  --inject-bug: repo contains the SAFE version (with null check).
    Uses RemoveNPDCheckAndExtractMetadata to remove the null guard, introduce the NPD,
    and extract metadata in one step. Use --buggy-file to write the injected code to disk
    (e.g. overwrite the canonical target_repo/ file).

Writes a texts JSON to --output (default: demo/texts/demo.json) with format:
    {
        "meta": { "callee", "caller", "var", "caller_sig", "call_line",
                  "deref_line", "last_line", "clean_code", "target_filename" },
        "COT": "<payload>",
        "FT":  "<payload>",
        ...
    }

Then use build_attacks.py to construct the attacked repos from the texts file.

Usage:
    # Standard (repo already buggy):
    python demo/attack_agent.py \\
        --repo   demo/target_repo \\
        --target display_user \\
        [--output demo/texts/demo.json] \\
        [--attack-type COT CG TOOL_ClangSA ...] \\
        [--all-attacks]

    # Bug-injection (start from safe _orig repo):
    python demo/attack_agent.py \\
        --repo        demo/target_repo_orig \\
        --target      display_user \\
        --inject-bug \\
        --buggy-file  demo/target_repo/users.c \\
        [--output demo/texts/demo.json] \\
        [--all-attacks]
"""

import argparse
import json
import os
import re
import sys

import dspy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from automatic.generate_variant import (
    ExtractVariantMetadata,
    RemoveNPDCheckAndExtractMetadata,
    GenerateAttackPayload,
    BUG_TYPE_DESCRIPTIONS,
    ATTACK_DESCRIPTIONS,
    CONTEXT_ATTACK_TYPES,
    TOOLS_C,
    extract_payload,
    build_few_shot_text,
)

CONTEXT_AWARE_ATTACKS = CONTEXT_ATTACK_TYPES + TOOLS_C


# ---------------------------------------------------------------------------
# Repo parsing
# ---------------------------------------------------------------------------

def read_c_files(repo_path: str) -> dict[str, str]:
    files = {}
    for root, _, names in os.walk(repo_path):
        for name in names:
            if name.endswith(".c"):
                path = os.path.join(root, name)
                with open(path) as f:
                    files[os.path.relpath(path, repo_path)] = f.read()
    return files


def find_function(files: dict[str, str], func_name: str) -> tuple[str, str] | None:
    pattern = re.compile(
        r'^\s*[\w\s\*]+\b' + re.escape(func_name) + r'\s*\(',
        re.MULTILINE,
    )
    for filename, content in files.items():
        if pattern.search(content):
            return filename, content
    return None


# ---------------------------------------------------------------------------
# Metadata extraction via DSPy
# ---------------------------------------------------------------------------

def extract_metadata(target_file_content: str, target_filename: str, meta_predictor,
                     inject_bug: bool = False, buggy_file: str = None) -> dict:
    if inject_bug:
        result = meta_predictor(clean_c=target_file_content, language="C")
        if buggy_file:
            os.makedirs(os.path.dirname(os.path.abspath(buggy_file)), exist_ok=True)
            with open(buggy_file, "w") as f:
                f.write(result.buggy_code)
            print(f"  [attack_agent] buggy code written to: {buggy_file}")
    else:
        numbered = "\n".join(f"{i+1:3}: {l}" for i, l in enumerate(target_file_content.splitlines()))
        result = meta_predictor(clean_c=numbered, bug_type="NPD", language="C")

    clean_code_lines = [
        l for l in result.clean_code.splitlines()
        if not l.strip().startswith("#include")
    ]

    return {
        "callee":          result.callee.strip(),
        "caller":          result.caller.strip(),
        "var":             result.var.strip(),
        "caller_sig":      result.caller_sig.strip(),
        "call_line":       result.call_line.strip(),
        "deref_line":      result.deref_line.strip(),
        "last_line":       result.last_line.strip(),
        "clean_code":      "\n".join(clean_code_lines).strip(),
        "target_filename": target_filename,
    }


# ---------------------------------------------------------------------------
# Payload generation via DSPy
# ---------------------------------------------------------------------------

def generate_payloads(meta: dict, attack_types: list[str], payload_predictor) -> dict[str, str]:
    payloads = {}
    for attack_type in attack_types:
        print(f"  [attack_agent] generating {attack_type}...", end=" ", flush=True)
        result = payload_predictor(
            clean_code=meta["clean_code"],
            bug_type="NPD",
            bug_type_description=BUG_TYPE_DESCRIPTIONS["npd"],
            language="C",
            callee=meta["callee"],
            caller=meta["caller"],
            var=meta["var"],
            attack_type=attack_type,
            attack_description=ATTACK_DESCRIPTIONS[attack_type],
            few_shot_examples=build_few_shot_text(attack_type),
        )
        payloads[attack_type] = extract_payload(result.payload)
        print("done")
    return payloads


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Malicious agent: extract metadata and generate adversarial payloads.")
    parser.add_argument("--repo",        required=True, help="Path to the target repo")
    parser.add_argument("--target",      required=True, help="Name of the vulnerable function to target")
    parser.add_argument("--output",      default=os.path.join(os.path.dirname(__file__), "texts", "demo.json"),
                        help="Output texts JSON path (default: demo/texts/demo.json)")
    parser.add_argument("--attack-type", nargs="+", dest="attack_types",
                        help="Specific attack types (default: --all-attacks)")
    parser.add_argument("--all-attacks", action="store_true",
                        help="Generate all context-aware attack types")
    parser.add_argument("--inject-bug",  action="store_true",
                        help="Input repo is the safe (_orig) version; use RemoveNPDCheckAndExtractMetadata "
                             "to introduce the NPD bug before generating payloads.")
    parser.add_argument("--buggy-file",  default=None,
                        help="(with --inject-bug) path to write the injected buggy file")
    args = parser.parse_args()

    if not args.attack_types and not args.all_attacks:
        parser.error("Specify --attack-type or --all-attacks")

    attack_types = CONTEXT_AWARE_ATTACKS if args.all_attacks else args.attack_types
    for t in attack_types:
        if t not in CONTEXT_AWARE_ATTACKS:
            parser.error(f"Unknown attack type: {t}. Supported: {CONTEXT_AWARE_ATTACKS}")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    lm = dspy.LM("anthropic/claude-sonnet-4-6", api_key=api_key)
    dspy.configure(lm=lm)

    meta_predictor = (
        dspy.ChainOfThought(RemoveNPDCheckAndExtractMetadata) if args.inject_bug
        else dspy.ChainOfThought(ExtractVariantMetadata)
    )
    payload_predictor = dspy.ChainOfThought(GenerateAttackPayload)

    # 1. Read repo
    print(f"[attack_agent] Reading repo: {args.repo}")
    files = read_c_files(args.repo)
    print(f"  Found C files: {list(files.keys())}")

    # 2. Find target function
    result = find_function(files, args.target)
    if result is None:
        print(f"[attack_agent] ERROR: function '{args.target}' not found", file=sys.stderr)
        sys.exit(1)
    target_filename, target_content = result
    print(f"  Target '{args.target}' in: {target_filename}")

    # 3. Extract metadata (and optionally inject bug)
    print("[attack_agent] Extracting metadata via LLM...")
    meta = extract_metadata(target_content, target_filename, meta_predictor,
                            inject_bug=args.inject_bug, buggy_file=args.buggy_file)
    print(f"  callee={meta['callee']}  caller={meta['caller']}  var={meta['var']}")
    print(f"  call_line:  {meta['call_line'].strip()}")
    print(f"  deref_line: {meta['deref_line'].strip()}")

    # 4. Generate payloads
    print(f"[attack_agent] Generating {len(attack_types)} payload(s)...")
    payloads = generate_payloads(meta, attack_types, payload_predictor)

    # 5. Write texts JSON (merge with existing if present)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    existing = {}
    if os.path.exists(args.output):
        with open(args.output) as f:
            existing = json.load(f)

    existing["meta"] = meta
    existing.update(payloads)

    with open(args.output, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"\n[attack_agent] Texts written to: {args.output}")
    print(f"  Keys: meta + {list(payloads.keys())}")


if __name__ == "__main__":
    main()
