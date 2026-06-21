"""
viewer_adaptive.py — FastAPI backend for the adaptive attacker loop viewer.

Usage:
    # Default: show vulnllmr_fromscratch + openvul_fromscratch side by side
    python attacker/adaptive/viewer_adaptive.py

    # Custom systems from a results root
    python attacker/adaptive/viewer_adaptive.py --systems vulnllm openvul

    # Legacy single-dir mode (system name = last path component)
    python attacker/adaptive/viewer_adaptive.py --exp-dir attacker/adaptive/results/vulnllmr_fromscratch
"""
import argparse
import difflib
import json
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

# Make result_analysis importable
_RESULT_ANALYSIS_DIR = Path(__file__).parents[1] / "result_analysis"
if str(_RESULT_ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(_RESULT_ANALYSIS_DIR))

STATIC_DIR = Path(__file__).parent / "adaptive_static"
RESULTS_DIR = Path(__file__).parent / "results"


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _annotation_diff(prev: str, curr: str, round_num: int) -> str | None:
    if prev is None:
        return None
    lines = list(difflib.unified_diff(
        prev.splitlines(keepends=True),
        curr.splitlines(keepends=True),
        fromfile=f"round_{round_num - 1}",
        tofile=f"round_{round_num}",
        n=5,
    ))
    return "".join(lines) if lines else ""


def _load_run(type_dir: Path) -> dict:
    result_path = type_dir / "result.json"
    if not result_path.exists():
        raise FileNotFoundError(f"No result.json in {type_dir}")

    result = json.loads(result_path.read_text())

    round_files = sorted(
        type_dir.glob("round_*.json"),
        key=lambda p: int(p.stem.split("_")[1]),
    )

    rounds = []
    prev_text: str | None = None
    for rf in round_files:
        r = json.loads(rf.read_text())
        curr_text = r.get("annotation_text", "")
        r["annotation_diff"] = _annotation_diff(prev_text, curr_text, int(r["round"]))
        prev_text = curr_text
        rounds.append(r)

    return {"result": result, "rounds": rounds}


def _scan_runs(systems_map: dict[str, Path]) -> list[dict]:
    runs = []
    for system_name, system_dir in systems_map.items():
        if not system_dir.exists():
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
                run_tag = result.get("run_tag", "")
                runs.append({
                    "slug": slug,
                    "system": system_name,
                    "type": ann_type,
                    "run_tag": run_tag,
                    "refiner_model": result.get("refiner_model", ""),
                    "final_verdict": result.get("final_verdict", "?"),
                    "stop_reason": result.get("stop_reason", "?"),
                    "rounds_used": result.get("rounds_used", 0),
                    "dir": str(type_dir),
                })
    return runs


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def build_app(systems_map: dict[str, Path], samples_dir: Path | None = None) -> FastAPI:
    app = FastAPI(title="Adaptive Attacker Viewer")

    _cache: dict = {"runs": None, "metrics": None}

    @app.get("/api/runs")
    def list_runs(refresh: bool = False):
        if refresh or _cache["runs"] is None:
            _cache["runs"] = _scan_runs(systems_map)
        return {"runs": _cache["runs"]}

    @app.get("/api/run")
    def get_run(slug: str = Query(...), type: str = Query(...),
                system: str = Query(...), tag: str = Query("")):
        if system not in systems_map:
            raise HTTPException(status_code=404, detail=f"Unknown system: {system!r}")
        system_dir = systems_map[system]
        suffix = f"_{tag}" if tag else ""
        type_dir = system_dir / f"repository_{slug}" / f"adaptive_{type}{suffix}"
        if not type_dir.exists():
            raise HTTPException(status_code=404, detail=f"No run for {system}/{slug}/{type}/{tag}")
        try:
            return _load_run(type_dir)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/metrics")
    def get_metrics(refresh: bool = False):
        if refresh or _cache["metrics"] is None:
            from metrics import (
                collect_system_results, compute_asr_cond, compute_cr, compute_delta_tpr,
            )
            out = {}
            for name, path in systems_map.items():
                if not path.exists():
                    continue
                repo_results = collect_system_results(path)
                out[name] = {
                    "asr_cond":  compute_asr_cond(repo_results),
                    "cr":        compute_cr(repo_results),
                    "delta_tpr": compute_delta_tpr(repo_results),
                }
            _cache["metrics"] = out
        return _cache["metrics"]

    @app.get("/api/baseline")
    def get_baseline(slug: str = Query(...), system: str = Query(...),
                     tag: str = Query("")):
        if system not in systems_map:
            raise HTTPException(status_code=404, detail=f"Unknown system: {system!r}")
        slug_dir = systems_map[system] / f"repository_{slug}"
        if not slug_dir.exists():
            raise HTTPException(status_code=404, detail=f"No slug dir for {system}/{slug}")

        # Find the baseline gate file for this run tag
        if tag:
            gate_path = slug_dir / f"baseline_gate_{tag}.json"
        else:
            gates = sorted(slug_dir.glob("baseline_gate_*.json"))
            gate_path = gates[0] if gates else None

        if not gate_path or not gate_path.exists():
            raise HTTPException(status_code=404, detail="No baseline gate file found")

        gate = json.loads(gate_path.read_text())

        # Load context.cc if samples_dir is configured
        code: str | None = None
        if samples_dir:
            cc = samples_dir / slug / "context.cc"
            if cc.exists():
                code = cc.read_text()

        return {"gate": gate, "code": code}

    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptive attacker loop viewer")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR,
                        help="Root directory containing system subdirs")
    parser.add_argument("--systems", nargs="+",
                        default=["vulnllmr_fromscratch", "openvul_fromscratch"],
                        help="System subdir names under --results-dir")
    parser.add_argument("--exp-dir", type=Path, default=None,
                        help="Legacy: single exp dir (system name = last component)")
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    if args.exp_dir:
        exp_path = args.exp_dir.resolve()
        systems_map = {exp_path.name: exp_path}
    else:
        results_dir = args.results_dir.resolve()
        systems_map = {s: results_dir / s for s in args.systems}

    # Default samples_dir: repo_cve_dataset_mining/samples_cve next to repo root
    repo_root = Path(__file__).parents[2]
    samples_dir = repo_root / "repo_cve_dataset_mining" / "samples_cve"
    if not samples_dir.exists():
        samples_dir = None

    app = build_app(systems_map=systems_map, samples_dir=samples_dir)
    print(f"Adaptive viewer at http://localhost:{args.port}")
    for name, path in systems_map.items():
        status = "✓" if path.exists() else "✗ (not found)"
        print(f"  {name}: {path}  {status}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
