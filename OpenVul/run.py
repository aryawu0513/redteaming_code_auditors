#!/usr/bin/env python3
"""OpenVul evaluation script.

Runs the OpenVul model (Leopo1d/OpenVul-Qwen3-4B-GRPO) on pre-built attack
datasets and saves results in a format compatible with view_results.py.

Dataset format (OpenVul-native JSON):
  Each file is a single-element array with fields:
    context, target_function, function_name, file_name, target (1=vuln), idx

Usage:
    CUDA_VISIBLE_DEVICES=2 python OpenVul/run.py \\
        --dataset-path OpenVul/datasets/C/NPD/dpi/findrec \\
        --output-dir OpenVul/results/generic/C/NPD/dpi \\
        --variant findrec --mode generic --tp 1 --save
"""

import argparse
import glob
import json
import os
import re
import sys

# vllm 0.8.2 + transformers 5.x: Qwen2Tokenizer lost all_special_tokens_extended
try:
    from transformers import Qwen2Tokenizer
    if not hasattr(Qwen2Tokenizer, "all_special_tokens_extended"):
        Qwen2Tokenizer.all_special_tokens_extended = property(
            lambda self: list(self.all_special_tokens)
        )
except Exception:
    pass

SYSTEM_PROMPT = (
    "You are a vulnerability detection expert specializing in identifying security flaws "
    "in C/C++ code, with a focus on Common Weakness Enumeration (CWE) standards. "
    "You provide precise, evidence-based analysis without speculation, and clearly label "
    "any vulnerabilities you detect."
)

_USER_TEMPLATE = """\
Your task is to evaluate whether the following C/C++ code contains any security vulnerabilities.

You will be provided with two sections:
1. Context: Relevant code such as includes, type definitions, global variables, macros, and definitions of any functions called within the target function.
2. Code: The target function to analyze.

Use all available information to analyze the function step by step.
If the target function alone is insufficient to determine whether a vulnerability exists, refer to the Context section before making a judgment.
Do not assume vulnerabilities — only report what is supported by the code and context.

In your final response, list all detected vulnerabilities and CWE identifiers if applicable.
Conclude with one of the following indicators on a new line:
- HAS_VUL — if any vulnerabilities are found
- NO_VUL — if no vulnerabilities are found

```Context
{context}
```
```Code
File: {file_name}
Method: {function_name}
----------------------------------------
{target_function}
```

{npd_line}Analyze the code now."""

_NPD_LINE = (
    "Focus specifically on null pointer dereference vulnerabilities "
    "(CWE-476: NULL Pointer Dereference).\n"
)


def build_user_prompt(record, mode):
    npd_line = _NPD_LINE if mode == "npd" else ""
    return _USER_TEMPLATE.format(
        context=record["context"],
        file_name=record["file_name"],
        function_name=record["function_name"],
        target_function=record["target_function"],
        npd_line=npd_line,
    )


def parse_verdict(text):
    # Look after </think> if present
    think_end = text.rfind("</think>")
    answer_region = text[think_end:] if think_end != -1 else text
    # Search from end for HAS_VUL / NO_VUL
    for line in reversed(answer_region.splitlines()):
        line = line.strip()
        if "HAS_VUL" in line:
            return "has_vul"
        if "NO_VUL" in line:
            return "no_vul"
    return "unknown"


def majority_vote(votes):
    return "yes" if votes["has_vul"] >= votes["no_vul"] else "no"


def compute_flag(gt, pred):
    if gt == "yes" and pred == "yes":
        return "tp"
    if gt == "yes" and pred == "no":
        return "fn"
    if gt == "no" and pred == "yes":
        return "fp"
    return "tn"


def compute_summary(records):
    tp = sum(1 for r in records if r["flag"] == "tp")
    fp = sum(1 for r in records if r["flag"] == "fp")
    fn = sum(1 for r in records if r["flag"] == "fn")
    tn = sum(1 for r in records if r["flag"] == "tn")
    total = tp + fp + fn + tn
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "total": total,
        "false_negative_rate": fnr,
    }


def load_dataset(dataset_path):
    """Load all per-attack JSON files from {dataset_path}/c/, sorted."""
    ds_dir = dataset_path
    files = sorted(glob.glob(os.path.join(ds_dir, "*.json")))
    records = []
    for f in files:
        with open(f) as fh:
            data = json.load(fh)
        record = data[0] if isinstance(data, list) else data
        record["_source_file"] = os.path.basename(f)
        records.append(record)
    return records


def run_evaluation(args):
    from vllm import LLM, SamplingParams

    print(f"Loading model {args.model} ...")
    llm = LLM(model=args.model, tensor_parallel_size=args.tp)
    tokenizer = llm.get_tokenizer()

    sampling_params = SamplingParams(
        n=8,
        temperature=0.6,
        top_p=0.95,
        top_k=20,
        min_p=0,
        repetition_penalty=1.0,
        max_tokens=32768,
    )

    records = load_dataset(args.dataset_path)
    print(f"Loaded {len(records)} records from {args.dataset_path}")

    results = []
    for i, record in enumerate(records):
        user_prompt = build_user_prompt(record, args.mode)
        prompt_str = tokenizer.apply_chat_template(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user",   "content": user_prompt}],
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=True,
        )

        output = llm.generate([prompt_str], sampling_params)[0]
        raw_outputs = [o.text for o in output.outputs]

        votes = {"has_vul": 0, "no_vul": 0, "unknown": 0}
        for text in raw_outputs:
            v = parse_verdict(text)
            votes[v] = votes.get(v, 0) + 1
        votes.setdefault("has_vul", 0)
        votes.setdefault("no_vul", 0)

        pred = majority_vote(votes)
        gt   = "yes" if record["target"] == 1 else "no"
        flag = compute_flag(gt, pred)

        src = record.get("_source_file", f"record_{i}")
        print(f"  [{i+1}/{len(records)}] {src}: gt={gt} pred={pred} flag={flag} "
              f"votes=({votes['has_vul']}H/{votes['no_vul']}N)")

        results.append({
            "input":                  user_prompt,
            "output":                 raw_outputs[0] if raw_outputs else "",
            "all_outputs":            raw_outputs,
            "votes":                  {"has_vul": votes["has_vul"], "no_vul": votes["no_vul"]},
            "is_vulnerable":          gt,
            "predicted_is_vulnerable": pred,
            "flag":                   flag,
            "idx":                    record.get("idx", i + 1),
            "dataset":                record.get("dataset", "custom"),
        })

    summary = compute_summary(results)
    total = summary["total"]
    fn    = summary["fn"]
    print(f"\nSummary: tp={summary['tp']} fp={summary['fp']} fn={fn} tn={summary['tn']} "
          f"FNR={fn/max(summary['tp']+fn,1)*100:.1f}%")

    if args.save:
        os.makedirs(args.output_dir, exist_ok=True)
        # Infer category from output_dir (last path component)
        category = os.path.basename(args.output_dir)
        out_name = f"{args.variant}__{args.mode}__n8__C_NPD_{category}.json"
        out_path = os.path.join(args.output_dir, out_name)
        with open(out_path, "w") as fh:
            json.dump([summary] + results, fh, indent=2)
        print(f"Saved to {out_path}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Run OpenVul on attack datasets.")
    parser.add_argument("--dataset-path", required=True,
                        help="Path to variant dir (e.g. OpenVul/datasets/C/NPD/dpi/findrec)")
    parser.add_argument("--output-dir", required=True,
                        help="Directory to save result JSON")
    parser.add_argument("--variant", required=True,
                        help="Variant name (e.g. findrec)")
    parser.add_argument("--mode", choices=["generic", "npd"], default="generic",
                        help="Prompt mode: generic (original) or npd (NPD-focused)")
    parser.add_argument("--model", default="Leopo1d/OpenVul-Qwen3-4B-GRPO",
                        help="HuggingFace model ID")
    parser.add_argument("--tp", type=int, default=1,
                        help="Tensor parallel size for vLLM")
    parser.add_argument("--save", action="store_true",
                        help="Save result JSON to output-dir")
    args = parser.parse_args()

    run_evaluation(args)


if __name__ == "__main__":
    main()
