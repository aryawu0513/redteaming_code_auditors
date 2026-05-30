"""
Rerun VulnLLM-R agentic scaffold BASELINE for the two missing/failed slugs:
  - 069A7F404506  (never ran)
  - A3BC94AC32E5  (ran but FN; overwrites scaffold_A3BC94AC32E5.json)

Writes to attacker/scaffold_results/scaffold_{SLUG}.json.
Run from the repo root:
    python scripts/run_scaffold_baseline_missing.py
"""
import gc
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
VLR_DIR   = REPO_ROOT / "VulnLLM-R"
RUNS_DIR  = REPO_ROOT / "attacker" / "runs" / "gpt-5.4-mini"
OUT_DIR   = REPO_ROOT / "attacker" / "scaffold_results"

sys.path.insert(0, str(VLR_DIR))
sys.path.insert(0, str(VLR_DIR / "vulscan" / "model_zoo" / "src"))

from agent_scaffold.scan import scan_project, make_vllm_fns  # noqa: E402

SLUGS = [
    "069A7F404506",   # baseline never run
    "A3BC94AC32E5",   # ran but FN — rerun overwrites
]

MODEL_NAME = "UCSB-SURFI/VulnLLM-R-7B"


def scan_solution(repo_dir: Path, model_fn, model_fn_diverse) -> list[dict]:
    """Copy only solution.c into a temp dir and run scan_project on it."""
    solution = repo_dir / "solution.c"
    if not solution.exists():
        raise FileNotFoundError(f"solution.c not found in {repo_dir}")
    with tempfile.TemporaryDirectory() as tmpdir:
        shutil.copy(solution, Path(tmpdir) / "solution.c")
        return scan_project(
            tmpdir,
            language="c",
            model_fn=model_fn,
            n_paths=2,
            max_rounds=3,
            policy_runs=4,
            model_fn_diverse=model_fn_diverse,
            target_functions=None,
            cwe_hints=None,
            verbose=True,
        )


def main():
    for slug in SLUGS:
        repo_dir = RUNS_DIR / f"repository_{slug}"
        out_file = OUT_DIR / f"scaffold_{slug}.json"

        print(f"\n{'='*60}")
        print(f"  SLUG: {slug}")
        if out_file.exists():
            print(f"  (overwriting existing {out_file.name})")
        print(f"{'='*60}")

        model_fn, model_fn_diverse = make_vllm_fns(MODEL_NAME, max_tokens=4096)

        try:
            results = scan_solution(repo_dir, model_fn, model_fn_diverse)
        except Exception as exc:
            print(f"ERROR: {exc}")
            results = []

        out_file.write_text(json.dumps(results, indent=2))
        print(f"\nResults saved to {out_file}")

        for r in results:
            flag = "VULN" if r.get("judge") == "yes" else "SAFE"
            print(f"  [{flag}]  {r.get('function')}  [{r.get('cwe_type')}]")

        del model_fn, model_fn_diverse
        gc.collect()
        try:
            import torch
            torch.cuda.empty_cache()
        except ImportError:
            pass

    print("\nDone.")


if __name__ == "__main__":
    main()
