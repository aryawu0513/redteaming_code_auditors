#!/usr/bin/env python3
"""Build results/index.json for the static HF Space viewer.

Walk the four systems under results/ and produce:
  { runs: [...], metrics: {...} }

Usage:
    # from inside the HF space (results/) or from the main repo:
    python build_hf_index.py
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent.resolve()
RESULTS_DIR = HERE
SYSTEMS = ["openvul_full", "openvul_full_b10", "vulnllmr_full", "vulnllmr_full_b10"]

sys.path.insert(0, str(HERE))
from metrics import collect_system_results, compute_asr_cond, compute_cr, compute_delta_tpr


def scan_runs(systems):
    runs = []
    for system in systems:
        system_dir = RESULTS_DIR / system
        if not system_dir.exists():
            print(f"  skipping {system} (not found)")
            continue
        for slug_dir in sorted(system_dir.glob("repository_*")):
            slug = slug_dir.name.replace("repository_", "")
            for type_dir in sorted(slug_dir.glob("adaptive_*")):
                result_path = type_dir / "result.json"
                if not result_path.exists():
                    continue
                try:
                    result = json.loads(result_path.read_text())
                except Exception:
                    continue
                ann_type = result.get("annotation_type") or type_dir.name.replace("adaptive_", "")
                runs.append({
                    "slug": slug,
                    "system": system,
                    "type": ann_type,
                    "run_tag": result.get("run_tag", ""),
                    "refiner_model": result.get("refiner_model", ""),
                    "final_verdict": result.get("final_verdict", "?"),
                    "stop_reason": result.get("stop_reason", "?"),
                    "rounds_used": result.get("rounds_used", 0),
                })
    return runs


def compute_metrics(systems):
    out = {}
    for system in systems:
        system_dir = RESULTS_DIR / system
        if not system_dir.exists():
            continue
        repo_results = collect_system_results(system_dir)
        out[system] = {
            "asr_cond":  compute_asr_cond(repo_results),
            "cr":        compute_cr(repo_results),
            "delta_tpr": compute_delta_tpr(repo_results),
        }
    return out


if __name__ == "__main__":
    print("Scanning runs...")
    runs = scan_runs(SYSTEMS)
    print(f"  {len(runs)} runs found")

    print("Computing metrics...")
    metrics = compute_metrics(SYSTEMS)
    for sys_name, m in metrics.items():
        asr = m["asr_cond"]["best"]["asr"]
        print(f"  {sys_name}: ASRcond best={asr:.1%}")

    out = {"runs": runs, "metrics": metrics}
    out_path = RESULTS_DIR / "index.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"Written {out_path}  ({out_path.stat().st_size // 1024} KB)")
