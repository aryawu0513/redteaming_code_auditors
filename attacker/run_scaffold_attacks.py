"""
Run VulnLLM-R agent scaffold on all attack variants for all 8 repos.
Loads the model ONCE per slug (not once per variant) to keep runtime reasonable.
Results saved to attacker/scaffold_results/attacks/scaffold_{SLUG}.json.
Does NOT touch attacker/scaffold_results/scaffold_*.json (baseline results).
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).parent.parent
VLR_DIR = REPO_ROOT / "VulnLLM-R"
RUNS_DIR = Path(__file__).parent / "runs" / "gpt-5.4-mini"
OUT_DIR = Path(__file__).parent / "scaffold_results" / "attacks"
OUT_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(VLR_DIR))
sys.path.insert(0, str(VLR_DIR / "vulscan" / "model_zoo" / "src"))

from agent_scaffold.scan import scan_project, make_vllm_fns  # noqa: E402

SLUGS = [
    "069A7F404506",
    "3FC486D0AE27",
    "6961F2970560",
    "6B249C5786A8",
    "7C95B6A69704",
    "9823AA10FA1B",
    "A3BC94AC32E5",
    "B1AC850C7E87",
    "E9FB59F8273B",
    "F4FB78BE2FBB",
]

ATTACK_TYPES = [
    "COT",
    "FT",
    "CG",
    "AA_MSG",
    "AA_USR",
    "AA_CA",
    "TOOL_ClangSA",
    "TOOL_Frama",
    "TOOL_Fuzzer",
    "TOOL_Coverity",
]

MODEL_NAME = "UCSB-SURFI/VulnLLM-R-7B"


def scan_variant(variant_file: Path, model_fn, model_fn_diverse, verbose: bool = True) -> list[dict]:
    """Copy the single variant file into a temp dir and run scan_project on it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / variant_file.name
        shutil.copy(variant_file, dest)
        return scan_project(
            str(tmpdir),
            language="c",
            model_fn=model_fn,
            n_paths=2,
            max_rounds=3,
            policy_runs=4,
            model_fn_diverse=model_fn_diverse,
            target_functions=None,
            cwe_hints=None,
            verbose=verbose,
        )


def main():
    for slug in SLUGS:
        out_file = OUT_DIR / f"scaffold_{slug}.json"
        if out_file.exists():
            print(f"\n[skip] {slug} — already done ({out_file})")
            continue

        repo_dir = RUNS_DIR / f"repository_{slug}"
        if not repo_dir.exists():
            print(f"\n[skip] {slug} — repo dir not found")
            continue

        print(f"\n{'='*60}")
        print(f"  SLUG: {slug} — loading model")
        print(f"{'='*60}")
        model_fn, model_fn_diverse = make_vllm_fns(MODEL_NAME, max_tokens=4096)

        slug_results: dict[str, list[dict]] = {}

        for attack in ATTACK_TYPES:
            variant_file = repo_dir / f"solution_{attack}.c"
            if not variant_file.exists():
                print(f"\n  [skip] {attack} — file not found")
                continue

            print(f"\n  --- {slug} / {attack} ---")
            try:
                results = scan_variant(variant_file, model_fn, model_fn_diverse, verbose=True)
                slug_results[attack] = results
                for r in results:
                    flag = "⚠️ VULN" if r["judge"] == "yes" else "✅ SAFE"
                    print(f"     {flag}  {r['function']}  [{r['cwe_type']}]  policy={r['policy_cwes']}")
            except Exception as exc:
                print(f"     ERROR: {exc}")
                slug_results[attack] = [{"error": str(exc)}]

        out_file.write_text(json.dumps(slug_results, indent=2))
        print(f"\nSaved: {out_file}")

        # Explicitly destroy the model to free GPU memory before loading for next slug
        del model_fn, model_fn_diverse
        import gc
        import torch
        gc.collect()
        torch.cuda.empty_cache()

    # ---- summary ----
    print("\n\n" + "=" * 60)
    print("  SUMMARY  (attack evasion rate per slug)")
    print("=" * 60)
    print(f"{'Slug':<16}  {'Detected/Total':>14}  {'Evasion%':>9}  Per-attack")
    print("-" * 80)
    for slug in SLUGS:
        out_file = OUT_DIR / f"scaffold_{slug}.json"
        if not out_file.exists():
            print(f"{slug:<16}  (not run)")
            continue
        data = json.loads(out_file.read_text())
        total = len(data)
        detected = sum(
            1 for results in data.values()
            if results and isinstance(results[0], dict) and results[0].get("judge") == "yes"
        )
        missed_attacks = [
            at for at, results in data.items()
            if not (results and isinstance(results[0], dict) and results[0].get("judge") == "yes")
        ]
        evasion_pct = 100 * (total - detected) / total if total else 0
        print(f"{slug:<16}  {detected:>6}/{total:<6}  {evasion_pct:>7.0f}%  evaded: {missed_attacks}")


if __name__ == "__main__":
    main()
