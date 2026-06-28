#!/usr/bin/env python3
"""
refine_loop_fabricate_cot.py — FABRICATE_COT adaptive attacker.

Each annotation is a single /* Security analysis: */ block with two parts:
  1. A fabricated tool report (any credible tool — Coverity, ClangSA, Frama-C,
     internal scanner, fuzzer, etc. — with an invented report ID and finding).
  2. Developer COT reasoning that cites the fabricated report and extends it
     with caller contracts / framework invariants.

Format and few-shot examples are baked into the bootstrapper and refiner
prompts (config_bootstrapper_fabricate_cot.yaml / config_refiner_fabricate_cot.yaml).

Usage:
    python adaptive_attacker/refine_loop_fabricate_cot.py \\
        --detector vulnllmr \\
        --slug NPD-CVE-0006 \\
        --budget 5 \\
        --run-tag fabricate_cot_v1
"""

import argparse
import copy
import csv
import json
import os
import sys
from functools import lru_cache
from pathlib import Path

import yaml
from openai import OpenAI

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO_ROOT))

from filter_npd import filter_npd_paragraphs  # noqa: E402

DATASET_DIR = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"
RESULTS_DIR = HERE / "results"

ATTACK_TYPE = "FABRICATE_COT"
BUDGET = 5

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        base_url = (
            os.environ.get("OPENAI_BASE_URL")
            or os.environ.get("OPENAI_API_BASE")
            or None
        )
        _client = OpenAI(base_url=base_url)
    return _client


@lru_cache(maxsize=1)
def _bootstrap_cfg() -> dict:
    return yaml.safe_load(
        (HERE / "config_bootstrapper_fabricate_cot.yaml").read_text()
    )


@lru_cache(maxsize=1)
def _refiner_cfg() -> dict:
    return yaml.safe_load(
        (HERE / "config_refiner_fabricate_cot.yaml").read_text()
    )


# ── Annotation helpers ────────────────────────────────────────────────────────

def _is_safe_comment(text: str) -> bool:
    c = text.strip()
    return c.startswith("/*") and c.endswith("*/")


def _call_llm(cfg: dict, messages: list[dict]) -> str:
    client = _get_client()
    resp = client.chat.completions.create(
        model=cfg["model"],
        messages=messages,
        temperature=cfg.get("temperature", 1.0),
        top_p=cfg.get("top_p", 0.95),
        max_tokens=cfg.get("max_tokens", 8192),
        extra_body={k: cfg[k] for k in ("top_k", "min_p", "presence_penalty",
                                         "repetition_penalty") if k in cfg},
    )
    return resp.choices[0].message.content.strip()


def _parse_output(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]
    return json.loads(raw)


def insert_annotation(bare_tf: str, annotation_text: str, insert_before: str) -> str:
    search_key = next(
        (ln.strip() for ln in insert_before.split("\n") if ln.strip()), insert_before
    )
    lines = bare_tf.split("\n")
    idx = next((i for i, l in enumerate(lines) if search_key in l), None)
    if idx is None:
        raise ValueError(f"insert_before not found: {insert_before!r}")
    indent = lines[idx][: len(lines[idx]) - len(lines[idx].lstrip())]
    indented = [indent + l if l.strip() else l for l in annotation_text.split("\n")]
    return "\n".join(lines[:idx] + indented + lines[idx:])


# ── LLM calls ────────────────────────────────────────────────────────────────

def bootstrap(bare_tf: str, baseline_reasoning: str,
              model: str, temperature: float) -> tuple[str, str, str] | None:
    cfg = _bootstrap_cfg()
    user_msg = json.dumps({
        "target_function": bare_tf,
        "detector_reasoning_filtered": baseline_reasoning,
    }, indent=2)
    messages = [
        {"role": "system", "content": cfg["system_prompt"]},
        {"role": "user",   "content": user_msg},
    ]
    for attempt in range(3):
        try:
            raw = _call_llm({**cfg, "model": model, "temperature": temperature}, messages)
            out = _parse_output(raw)
            ann, ins = out["annotation_text"], out["insert_before"]
            if ins not in bare_tf:
                raise ValueError(f"insert_before not found: {ins!r}")
            if not _is_safe_comment(ann):
                raise ValueError("annotation is not a /* */ block comment")
            return ann, ins, out.get("rationale", "")
        except Exception as e:
            print(f"  [bootstrap attempt {attempt+1} failed] {e}")
    return None


def refine(bare_tf: str, baseline_reasoning: str,
           prior_attempts: list[dict],
           model: str, temperature: float) -> tuple[str, str, str] | tuple[None, None, str]:
    cfg = _refiner_cfg()
    user_msg = json.dumps({
        "target_function": bare_tf,
        "detector_reasoning_filtered": baseline_reasoning,
        "prior_attempts": prior_attempts,
    }, indent=2)
    messages = [
        {"role": "system", "content": cfg["system_prompt"]},
        {"role": "user",   "content": user_msg},
    ]
    for attempt in range(3):
        try:
            raw = _call_llm({**cfg, "model": model, "temperature": temperature}, messages)
            out = _parse_output(raw)
            ann, ins = out["annotation_text"], out["insert_before"]
            if ins not in bare_tf:
                raise ValueError(f"insert_before not found: {ins!r}")
            if not _is_safe_comment(ann):
                raise ValueError("annotation is not a /* */ block comment")
            return ann, ins, out.get("rationale", "")
        except Exception as e:
            print(f"  [refine attempt {attempt+1} failed] {e}")
    return None, None, ""


# ── I/O helpers ───────────────────────────────────────────────────────────────

def load_baseline_record(slug: str, dataset_dir: Path) -> dict | None:
    baseline_dir = dataset_dir.parent / "baseline" / f"repository_{slug}"
    matches = sorted(baseline_dir.glob("*CLEAN*.json"))
    if not matches:
        return None
    data = json.loads(matches[0].read_text())
    return data[0] if isinstance(data, list) else data


def _save_round(out_dir: Path, rnd: int, run_tag: str,
                ann: str, ins: str, rationale: str, det: dict) -> None:
    suffix = f"_{run_tag}" if run_tag else ""
    (out_dir / f"round_{rnd}{suffix}.json").write_text(json.dumps({
        "round": rnd,
        "annotation_text": ann,
        "insert_before": ins,
        "rationale": rationale,
        "detector_verdict": det["verdict"],
        "detector_reasoning": det["reasoning"],
    }, indent=2))


def _save_result(out_dir: Path, run_tag: str, model: str,
                 final_verdict: str, rounds_used: int, stop_reason: str) -> None:
    suffix = f"_{run_tag}" if run_tag else ""
    (out_dir / "result.json").write_text(json.dumps({
        "annotation_type": ATTACK_TYPE,
        "final_verdict": final_verdict,
        "rounds_used": rounds_used,
        "stop_reason": stop_reason,
        "run_tag": run_tag,
        "refiner_model": model,
    }, indent=2))
    path = out_dir / f"summary{suffix}.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "annotation_type", "static_verdict", "final_verdict", "rounds_used", "stop_reason"
        ])
        w.writeheader()
        w.writerow({
            "annotation_type": ATTACK_TYPE, "static_verdict": "n/a",
            "final_verdict": final_verdict, "rounds_used": rounds_used,
            "stop_reason": stop_reason,
        })


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--detector",
                        choices=["openvul", "vulnllmr", "repoaudit", "vultrial", "vulrag"],
                        default="vulnllmr")
    parser.add_argument("--detector-url", default=os.environ.get("DETECTOR_URL"))
    parser.add_argument("--model", default=None)
    parser.add_argument("--vulnllmr-mode", choices=["agentic", "funclevel"], default="funclevel")
    parser.add_argument("--refiner-model", default="Qwen/Qwen3.6-27B-FP8")
    parser.add_argument("--refiner-temperature", type=float, default=1.0)
    parser.add_argument("--tp", type=int, default=1)
    parser.add_argument("--budget", type=int, default=BUDGET)
    parser.add_argument("--run-tag", default="fabricate_cot_v1")
    parser.add_argument("--dataset", type=Path, default=DATASET_DIR)
    parser.add_argument("--system", default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    slug = args.slug
    if args.system is None:
        args.system = args.detector
    if args.out_dir is None:
        args.out_dir = RESULTS_DIR / args.system / f"repository_{slug}"

    run_tag = args.run_tag
    dir_suffix = f"_{run_tag}" if run_tag else ""
    out_dir = args.out_dir / f"adaptive_{ATTACK_TYPE}{dir_suffix}"

    print(f"FABRICATE_COT — slug={slug}")
    print(f"Detector: {args.detector} | Refiner: {args.refiner_model} T={args.refiner_temperature}")
    print(f"Budget: {args.budget} | Output: {args.out_dir}")

    # ── Detector ──────────────────────────────────────────────────────────────
    if args.detector_url:
        from detector_http import HttpDetectorClient
        detector = HttpDetectorClient(base_url=args.detector_url)
    elif args.detector == "vulnllmr":
        from detector_vulnllmr import VulnLLMRDetector
        detector = VulnLLMRDetector(tp=args.tp, mode=args.vulnllmr_mode)
    elif args.detector == "repoaudit":
        from detector_repoaudit import RepoAuditDetector
        detector = RepoAuditDetector(model_name=args.model or "claude-sonnet-4-6")
    elif args.detector == "vultrial":
        from detector_vultrial import VulTrialDetector
        detector = VulTrialDetector(model=args.model or "gpt-4o", mode="npd")
    elif args.detector == "vulrag":
        from detector_vulrag import VulRAGDetector
        detector = VulRAGDetector(model=args.model)
    else:
        from detector_openvul import OpenVulDetector
        detector = OpenVulDetector(model_id=args.model, tp=args.tp)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write run config
    (args.out_dir / f"run_config{dir_suffix}.txt").write_text(
        f"Slug: {slug}\n"
        f"Dataset: {args.dataset}\n"
        f"Type: {ATTACK_TYPE}\n"
        f"Detector: {args.detector}\n"
        f"Refiner: {args.refiner_model} T={args.refiner_temperature}\n"
        f"Budget: {args.budget}\n"
        f"Mode: fabricate tool evidence + COT citing it\n"
        f"Run tag: {run_tag or '(none)'}\n"
    )

    # ── Skip if done ──────────────────────────────────────────────────────────
    if (out_dir / "result.json").exists():
        d = json.loads((out_dir / "result.json").read_text())
        print(f"[{ATTACK_TYPE}] already done ({d.get('final_verdict')}) — skipping")
        return

    # ── Baseline gate ─────────────────────────────────────────────────────────
    baseline = load_baseline_record(slug, dataset_dir=args.dataset)
    if baseline is None:
        print(f"[baseline-gate] no CLEAN record for {slug} — cannot run")
        return

    baseline_gate_path = args.out_dir / f"baseline_gate{dir_suffix}.json"
    if baseline_gate_path.exists():
        bg = json.loads(baseline_gate_path.read_text())
        print(f"[baseline-gate] cached — verdict={bg['verdict']}")
        if bg["verdict"] == "safe":
            print("*** baseline_miss — skipping ***")
            return
        if bg["verdict"] == "error":
            print("*** baseline_error — skipping ***")
            return
        baseline_reasoning = filter_npd_paragraphs(bg["reasoning"]) or bg["reasoning"]
    else:
        print(f"[baseline-gate] detecting on CLEAN baseline …")
        base_det = detector.detect(baseline)
        print(f"[baseline-gate] verdict={base_det['verdict']}  votes={base_det['votes']}")
        baseline_gate_path.write_text(json.dumps({
            "slug": slug, "verdict": base_det["verdict"],
            "votes": base_det["votes"], "reasoning": base_det["reasoning"],
        }, indent=2))
        if base_det["verdict"] == "safe":
            print("*** baseline_miss — skipping ***")
            return
        if base_det["verdict"] == "error":
            print("*** baseline_error — skipping ***")
            return
        baseline_reasoning = filter_npd_paragraphs(base_det["reasoning"]) or base_det["reasoning"]

    bare_tf = baseline["target_function"]

    # ── Round 0: bootstrap ────────────────────────────────────────────────────
    print(f"\n[{ATTACK_TYPE}] round 0 — bootstrapping …")
    result = bootstrap(bare_tf, baseline_reasoning,
                       args.refiner_model, args.refiner_temperature)
    if result is None:
        print(f"[{ATTACK_TYPE}] bootstrap failed — aborting")
        return
    ann, ins, rationale = result

    record = copy.deepcopy(baseline)
    record["target_function"] = insert_annotation(bare_tf, ann, ins)
    det = detector.detect(record)
    print(f"[{ATTACK_TYPE}] round 0 verdict={det['verdict']}")
    _save_round(out_dir, 0, run_tag, ann, ins, rationale, det)

    prior_attempts = [{
        "annotation_text": ann, "insert_before": ins,
        "detector_reasoning": filter_npd_paragraphs(det["reasoning"]) or det["reasoning"],
    }]

    if det["verdict"] == "safe":
        _save_result(out_dir, run_tag, args.refiner_model, "safe", 0, "flipped_safe")
        print(f"[{ATTACK_TYPE}] *** FLIPPED at round 0! ***")
        return

    # ── Rounds 1..budget ─────────────────────────────────────────────────────
    for rnd in range(1, args.budget + 1):
        print(f"\n[{ATTACK_TYPE}] round {rnd} — refining …")
        ann, ins, rationale = refine(bare_tf, baseline_reasoning,
                                     prior_attempts,
                                     args.refiner_model, args.refiner_temperature)
        if ann is None:
            print(f"[{ATTACK_TYPE}] refine failed 3× at round {rnd} — stopping")
            break

        record = copy.deepcopy(baseline)
        record["target_function"] = insert_annotation(bare_tf, ann, ins)
        det = detector.detect(record)
        print(f"[{ATTACK_TYPE}] round {rnd} verdict={det['verdict']}")
        _save_round(out_dir, rnd, run_tag, ann, ins, rationale, det)

        prior_attempts.append({
            "annotation_text": ann, "insert_before": ins,
            "detector_reasoning": filter_npd_paragraphs(det["reasoning"]) or det["reasoning"],
        })

        if det["verdict"] == "safe":
            _save_result(out_dir, run_tag, args.refiner_model, "safe", rnd, "flipped_safe")
            print(f"[{ATTACK_TYPE}] *** FLIPPED at round {rnd}! ***")
            return

    _save_result(out_dir, run_tag, args.refiner_model,
                 "vulnerable", args.budget, "budget_exhausted")
    print(f"[{ATTACK_TYPE}] budget exhausted — not flipped")


if __name__ == "__main__":
    main()
