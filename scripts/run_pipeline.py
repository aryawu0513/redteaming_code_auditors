#!/usr/bin/env python3
"""
run_pipeline.py — Flag-driven launcher for benchmark steps.

Steps:
  attacker  : run Qwen attacker to generate payloads
  build     : build unified benchmark JSONs from attacker runs
  eval      : run system on baseline + context_aware
  round0    : baseline-gated run (skip context_aware if baseline miss)
  adaptive  : adaptive refinement loop (OpenVul / VulnLLM-R only)
  all       : attacker → build → eval → round0 → adaptive
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent

LCB_SLUGS = [
    "069A7F404506", "3FC486D0AE27", "6961F2970560", "6B249C5786A8",
    "7C95B6A69704", "9823AA10FA1B", "A3BC94AC32E5", "B1AC850C7E87",
]
SOFA_SLUGS = ["NPD-1", "NPD-2", "NPD-3"]


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> None:
    print("  $", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def attacker_step(args) -> None:
    if args.benchmark == "leetcodebench":
        runs_dir = Path(args.runs_dir or REPO_ROOT / "attacker" / "runs" / "qwen3.6-27b")
        if args.slugs:
            dirs = [str(runs_dir / f"repository_{s}") for s in args.slugs]
        else:
            dirs = [str(p) for p in runs_dir.glob("repository_*")]
        cmd = ["bash", str(REPO_ROOT / "scripts" / "run_attacker_qwen.sh"), *dirs]
        run(cmd)
    else:
        print("NOTE: sofa attacker run not wired here; use a dedicated attacker run if needed.")


def build_step(args) -> None:
    if args.benchmark == "leetcodebench":
        runs_dir = args.runs_dir or str(REPO_ROOT / "attacker" / "runs" / "qwen3.6-27b")
        out_root = args.dataset_root or str(REPO_ROOT / "benchmark" / "leetcodebench_qwen")
        cmd = [
            sys.executable, str(REPO_ROOT / "attacker" / "build_eval_datasets.py"),
            "--runs-dir", runs_dir,
            "--out-root", out_root,
        ]
        run(cmd)
    else:
        runs_dir = args.runs_dir or str(REPO_ROOT / "attacker" / "runs" / "qwen3.6-27b")
        out_root = args.dataset_root or str(REPO_ROOT / "benchmark" / "sofa_qwen3_27b")
        cmd = [
            sys.executable, str(REPO_ROOT / "attacker" / "build_eval_datasets_cpp.py"),
            "--runs-dir", runs_dir,
            "--out-root", out_root,
            "--dataset", "sofa-pbrpc-npd",
        ]
        run(cmd)


def eval_step(args) -> None:
    dataset_root = args.dataset_root or (
        str(REPO_ROOT / "benchmark" / "leetcodebench_qwen")
        if args.benchmark == "leetcodebench"
        else str(REPO_ROOT / "benchmark" / "sofa_qwen3_27b")
    )
    variants = args.variants or (
        " ".join(f"repository_{s}" for s in (args.slugs or (LCB_SLUGS if args.benchmark == "leetcodebench" else SOFA_SLUGS)))
    )
    env = os.environ.copy()
    env["DATASET_ROOT"] = dataset_root
    env["VARIANTS"] = variants
    env["SYSTEM"] = args.system
    run(["bash", str(REPO_ROOT / "scripts" / "run_benchmark_system.sh")], env=env)


def _vulnllm_output_path(dataset_path: Path, output_dir: Path, model: str,
                         max_tokens: int, n: int, language: str) -> Path:
    try:
        rel = dataset_path.relative_to(REPO_ROOT / "VulnLLM-R")
        dataset_name = str(rel).replace("/", "_")
    except ValueError:
        dataset_name = "_".join(dataset_path.parts[-2:])
    model_parts = model.split("/")
    if len(model_parts) > 2:
        model_short = f"{model_parts[-2]}_{model_parts[-1]}"
    else:
        model_short = model_parts[-1]
    return output_dir / f"{max_tokens}__{n}__{dataset_name}__full__cot__{language}__policy__{model_short}.json"


def round0_step(args) -> None:
    if args.system == "openvul":
        dataset_root = args.dataset_root or str(REPO_ROOT / "benchmark" / "leetcodebench_qwen")
        results_root = args.results_root or str(REPO_ROOT / "OpenVul" / "results" / "leetcodebench_qwen")
        cmd = [
            sys.executable, str(REPO_ROOT / "OpenVul" / "run_local_bench_gated.py"),
            "--dataset-root", dataset_root,
            "--output-root", results_root,
            "--model", args.model or "Leopo1d/OpenVul-Qwen3-4B-GRPO",
            "--tp", "1", "--n", "1", "--mode", "npd", "--save",
            "--slugs", *(args.slugs or LCB_SLUGS),
        ]
        run(cmd)
        return

    if args.system == "vulnllm":
        dataset_root = Path(args.dataset_root or REPO_ROOT / "benchmark" / "leetcodebench_qwen")
        results_root = Path(args.results_root or REPO_ROOT / "VulnLLM-R" / "results" / "C" / "NPD" / "policy_qwen")
        model = args.model or "UCSB-SURFI/VulnLLM-R-7B"
        language = "c"
        max_tokens = 4096
        n = 1
        for slug in (args.slugs or LCB_SLUGS):
            base_path = dataset_root / "baseline" / f"repository_{slug}"
            ctx_path = dataset_root / "context_aware" / f"repository_{slug}"
            if not base_path.exists():
                print(f"SKIP {slug}: missing baseline")
                continue
            cmd = [
                sys.executable, "-m", "vulscan.test.test",
                "--output_dir", str(results_root / "baseline"),
                "--dataset_path", str(base_path),
                "--language", language,
                "--model", model,
                "--use_cot", "--use_policy", "--vllm",
                "--tp", "1", "--max_tokens", str(max_tokens),
                "--save",
            ]
            run(cmd, cwd=REPO_ROOT / "VulnLLM-R")
            out_file = _vulnllm_output_path(base_path, results_root / "baseline", model, max_tokens, n, language)
            if not out_file.exists():
                print(f"SKIP {slug}: baseline output not found at {out_file}")
                continue
            data = __import__("json").loads(out_file.read_text())
            flag = data[1].get("flag") if len(data) > 1 else None
            if flag != "tp":
                print(f"SKIP {slug}: baseline flag={flag}")
                continue
            if not ctx_path.exists():
                print(f"SKIP {slug}: missing context_aware")
                continue
            cmd = [
                sys.executable, "-m", "vulscan.test.test",
                "--output_dir", str(results_root / "context_aware"),
                "--dataset_path", str(ctx_path),
                "--language", language,
                "--model", model,
                "--use_cot", "--use_policy", "--vllm",
                "--tp", "1", "--max_tokens", str(max_tokens),
                "--save",
            ]
            run(cmd, cwd=REPO_ROOT / "VulnLLM-R")
        return

    print(f"Round-0 gating not implemented for system={args.system}.")


def adaptive_step(args) -> None:
    if args.system not in ("openvul", "vulnllm", "repoaudit", "vultrial"):
        print(f"Adaptive loop only supports openvul/vulnllm/repoaudit/vultrial. system={args.system}")
        return
    dataset_root = args.dataset_root or str(REPO_ROOT / "benchmark" / "leetcodebench_qwen" / "context_aware")
    run_tag = args.run_tag or f"{args.system}_adaptive"
    # If a detector URL is given (or DETECTOR_URL is set), talk to an already-served
    # detector over HTTP instead of loading one in-process. The URL takes over, so
    # the in-process --detector flag is omitted.
    detector_url = args.detector_url or os.environ.get("DETECTOR_URL")
    for slug in (args.slugs or LCB_SLUGS):
        cmd = [
            sys.executable, str(REPO_ROOT / "attacker" / "adaptive" / "refine_loop.py"),
            "--slug", slug,
            "--dataset", dataset_root,
            "--system", args.system,
            "--refiner-model", args.refiner_model or "Qwen/Qwen3.6-27B-FP8",
            "--refiner-temperature", "1.0",
            "--budget", str(args.budget),
            "--run-tag", run_tag,
        ]
        if detector_url:
            cmd += ["--detector-url", detector_url]
        elif args.system == "vulnllm":
            cmd += ["--detector", "vulnllmr"]
        elif args.system == "repoaudit":
            cmd += ["--detector", "repoaudit"]
        elif args.system == "vultrial":
            cmd += ["--detector", "vultrial"]
        if args.no_baseline_gate:
            cmd += ["--no-baseline-gate"]
        run(cmd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", choices=["leetcodebench", "sofa"], default="leetcodebench")
    parser.add_argument("--system", choices=["openvul", "vulnllm", "vultrial", "repoaudit"], required=True)
    parser.add_argument("--step", choices=["attacker", "build", "eval", "round0", "adaptive", "all"], default="eval")
    parser.add_argument("--runs-dir", default=None)
    parser.add_argument("--dataset-root", default=None)
    parser.add_argument("--results-root", default=None)
    parser.add_argument("--slugs", nargs="+", default=None)
    parser.add_argument("--variants", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--run-tag", default=None)
    parser.add_argument("--refiner-model", dest="refiner_model", default=None)
    parser.add_argument("--budget", type=int, default=5)
    parser.add_argument("--detector-url", dest="detector_url", default=None,
                        help="Adaptive step only: talk to an already-served detector "
                             "(scripts/serve_detector_*.sh) at this URL instead of "
                             "loading one in-process. Also read from env DETECTOR_URL.")
    parser.add_argument("--no-baseline-gate", dest="no_baseline_gate", action="store_true",
                        help="Adaptive step only: disable the per-slug baseline pre-check "
                             "(by default the loop skips a slug whose CLEAN baseline the "
                             "detector does not flag as vulnerable).")
    args = parser.parse_args()

    if args.step in ("attacker", "all"):
        print("\n== Step: attacker ==")
        attacker_step(args)
    if args.step in ("build", "all"):
        print("\n== Step: build ==")
        build_step(args)
    if args.step in ("eval", "all"):
        print("\n== Step: eval ==")
        eval_step(args)
    if args.step in ("round0", "all"):
        print("\n== Step: round0 (baseline-gated) ==")
        round0_step(args)
    if args.step in ("adaptive", "all"):
        print("\n== Step: adaptive ==")
        adaptive_step(args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
