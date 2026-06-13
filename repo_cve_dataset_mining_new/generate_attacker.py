#!/usr/bin/env python3
"""
One-shot attacker code generation for CVE NPD benchmark.

For each viable sample, sends task.md + starter.cc (+ auxiliary.cc if present)
to the model and saves the filled-in implementation as attacker_output.cc.

Usage:
  python3 repo_cve_dataset_mining_new/generate_attacker.py \\
      repo_cve_dataset_mining_new/f3_nolimit_dedup_func.jsonl \\
      [--samples-dir repo_cve_dataset_mining_new/samples_cve_fix] \\
      [--model qwen3.6-27b] [--base-url http://localhost:8007/v1] \\
      [--workers 4] [--force]
"""

import json
import re
import threading
from pathlib import Path
from openai import OpenAI
import yaml

HERE            = Path(__file__).parent
DEFAULT_SAMPLES = HERE / "samples_cve_fix"
DEFAULT_CONFIG  = HERE / "config_cve_attacker.yaml"
MODEL           = "qwen3.6-27b"
BASE_URL        = "http://localhost:8007/v1"

_PRINT_LOCK = threading.Lock()


def load_config(config_path: Path) -> dict:
    return yaml.safe_load(config_path.read_text())


def render_user_prompt(cfg: dict, task_md: str, starter: str,
                       auxiliary: str, headers: str, lang: str,
                       repo_name: str = "", file_name: str = "") -> str:
    lang_label = "C++" if lang == "cpp" else "C"
    headers_section = (
        f"\n=== headers.h (project headers) ===\n{headers.strip()}\n"
        if headers.strip() else ""
    )
    auxiliary_section = (
        f"\n=== auxiliary context ({repo_name}) ===\n{auxiliary.strip()}\n"
        if auxiliary.strip() else ""
    )
    return cfg["instance_template"].format_map({
        "lang_label":        lang_label,
        "repo_name":         repo_name,
        "file_name":         file_name,
        "task_md":           task_md.strip(),
        "starter":           starter.strip(),
        "headers_section":   headers_section,
        "auxiliary_section": auxiliary_section,
    })


def call_llm(cfg: dict, task_md: str, starter: str, auxiliary: str, headers: str,
             client: OpenAI, lang: str = "c",
             prev_code: str = "", error_output: str = "",
             repo_name: str = "", file_name: str = "") -> str:
    temperature = cfg.get("model", {}).get("temperature", 0.0)
    messages = [
        {"role": "system", "content": cfg["system_template"].strip()},
        {"role": "user",   "content": render_user_prompt(
            cfg, task_md, starter, auxiliary, headers, lang, repo_name, file_name)},
    ]
    if prev_code and error_output:
        messages.append({"role": "assistant", "content": prev_code})
        messages.append({"role": "user", "content":
            cfg["error_template"].format_map({"error_output": error_output}).strip()})
    resp = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=temperature,
    )
    raw = (resp.choices[0].message.content or "").strip()
    raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```$",       "", raw, flags=re.MULTILINE)
    return raw.strip()


def process_one(pid: str, row: dict, samples_dir: Path, output_dir: Path,
                client: OpenAI, cfg: dict, force: bool, with_error: bool = False) -> str:
    d       = samples_dir / pid   # read inputs from here
    out_d   = output_dir / pid    # write outputs here
    out_path = out_d / "attacker_output.cc"

    if not force and out_path.exists():
        return "skip"

    if not (d / "repo_testsuite_pass").exists():
        return "skip_not_viable"
    if (d / "context_too_large").exists():
        return "skip_too_large"
    if not (d / "task.md").exists() or not (d / "starter.cc").exists():
        return "skip_no_task"

    task_md   = (d / "task.md").read_text()
    starter   = (d / "starter.cc").read_text()
    auxiliary = (d / "raw_auxiliary.cc").read_text() if (d / "raw_auxiliary.cc").exists() else ""
    headers   = (d / "raw_headers.h").read_text() if (d / "raw_headers.h").exists() else ""
    lang      = row.get("lang") or ("cpp" if starter.startswith("//") else "c")
    meta_path = d / "metadata.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        lang = meta.get("lang") or row.get("lang") or "c"

    repo_url  = row.get("repo_url", "")
    repo_name = repo_url.replace("https://github.com/", "").rstrip("/") if repo_url else ""
    file_name = row.get("file_path") or row.get("file") or ""

    prev_code    = ""
    error_output = ""
    if with_error and (out_d / "attacker_result.json").exists() and out_path.exists():
        prev = json.loads((out_d / "attacker_result.json").read_text())
        error_output = prev.get("error_output", "") or ""
        prev_code    = out_path.read_text() if error_output else ""

    try:
        output = call_llm(cfg, task_md, starter, auxiliary, headers, client, lang,
                          prev_code, error_output, repo_name, file_name)
    except Exception as e:
        with _PRINT_LOCK:
            print(f"  {pid}: LLM error — {e}")
        return "fail"

    out_d.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output)
    with _PRINT_LOCK:
        fn = row.get("func_name", row.get("function", ""))
        aux_note = "  +aux" if auxiliary else ""
        err_note = "  +err" if error_output else ""
        print(f"  {pid}: OK  ({fn}{aux_note}{err_note}  {len(output)} chars)")
    return "ok"


def main():
    global MODEL
    import argparse
    ap = argparse.ArgumentParser(description="One-shot attacker code generation")
    ap.add_argument("jsonl")
    ap.add_argument("ids",           nargs="*", help="Pilot IDs to process (default: all)")
    ap.add_argument("--ids-file",    help="File with one pilot ID per line")
    ap.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES),
                    help="Directory with pipeline inputs (task.md, starter.cc, etc.)")
    ap.add_argument("--output-dir",  default=None,
                    help="Directory to write attacker_output.cc (default: --samples-dir)")
    ap.add_argument("--model",       default=MODEL)
    ap.add_argument("--base-url",    default=BASE_URL)
    ap.add_argument("--workers",     type=int, default=1)
    ap.add_argument("--force",       action="store_true")
    ap.add_argument("--with-error",  action="store_true",
                    help="Append error_output from attacker_result.json as feedback")
    ap.add_argument("--config",      default=str(DEFAULT_CONFIG),
                    help="YAML config file for prompts")
    args = ap.parse_args()

    MODEL = args.model
    cfg   = load_config(Path(args.config))

    samples_dir = Path(args.samples_dir)
    output_dir  = Path(args.output_dir) if args.output_dir else samples_dir
    rows = {json.loads(l)["pilot_id"]: json.loads(l)
            for l in Path(args.jsonl).read_text().splitlines() if l.strip()}

    if args.ids_file:
        pids = [l.strip() for l in Path(args.ids_file).read_text().splitlines() if l.strip()]
        pids = [p for p in pids if p in rows]
    elif args.ids:
        pids = [p for p in args.ids if p in rows]
    else:
        pids = list(rows.keys())

    # Filter to viable
    pids = [p for p in pids
            if (samples_dir / p / "repo_testsuite_pass").exists()
            and not (samples_dir / p / "context_too_large").exists()
            and (samples_dir / p / "task.md").exists()]

    print(f"Generating for {len(pids)} samples\n  inputs  → {samples_dir}/\n  outputs → {output_dir}/\n")
    client = OpenAI(api_key="placeholder", base_url=args.base_url)

    counts: dict[str, int] = {}

    if args.workers == 1:
        for pid in pids:
            status = process_one(pid, rows[pid], samples_dir, output_dir, client, cfg, args.force, args.with_error)
            counts[status] = counts.get(status, 0) + 1
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run(pid):
            return pid, process_one(pid, rows[pid], samples_dir, output_dir, client, cfg, args.force, args.with_error)

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            for fut in as_completed(ex.submit(_run, p) for p in pids):
                try:
                    _, status = fut.result()
                    counts[status] = counts.get(status, 0) + 1
                except Exception as e:
                    print(f"  ERROR: {e}")
                    counts["fail"] = counts.get("fail", 0) + 1

    print(f"\nDone: {counts}")


if __name__ == "__main__":
    main()
