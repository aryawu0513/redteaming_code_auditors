"""
viewer_adaptive.py — FastAPI backend for the adaptive attacker loop viewer.

Usage:
    python attacker/adaptive/viewer_adaptive.py
    python attacker/adaptive/viewer_adaptive.py --port 8002
    python attacker/adaptive/viewer_adaptive.py --exp-dir attacker/adaptive/results
"""
import argparse
import difflib
import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).parent / "adaptive_static"


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


def _scan_runs(exp_dir: Path) -> list[dict]:
    runs = []
    for slug_dir in sorted(exp_dir.glob("repository_*")):
        slug = slug_dir.name.replace("repository_", "")
        for type_dir in sorted(slug_dir.glob("adaptive_*")):
            result_path = type_dir / "result.json"
            if not result_path.exists():
                continue
            try:
                result = json.loads(result_path.read_text())
            except Exception:
                continue
            # Prefer annotation_type from result.json (authoritative).
            # run_tag may be absent in older runs → default "".
            ann_type = result.get("annotation_type") or type_dir.name.replace("adaptive_", "")
            run_tag = result.get("run_tag", "")
            runs.append({
                "slug": slug,
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

def build_app(exp_dir: str = "attacker/adaptive/results") -> FastAPI:
    exp_path = Path(exp_dir).resolve()
    app = FastAPI(title="Adaptive Attacker Viewer")

    _cache: dict = {"runs": None}

    @app.get("/api/runs")
    def list_runs(refresh: bool = False):
        if refresh or _cache["runs"] is None:
            _cache["runs"] = _scan_runs(exp_path)
        return {"runs": _cache["runs"]}

    @app.get("/api/run")
    def get_run(slug: str = Query(...), type: str = Query(...), tag: str = Query("")):
        suffix = f"_{tag}" if tag else ""
        type_dir = exp_path / f"repository_{slug}" / f"adaptive_{type}{suffix}"
        if not type_dir.exists():
            raise HTTPException(status_code=404, detail=f"No adaptive run for {slug}/{type}/{tag}")
        try:
            return _load_run(type_dir)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptive attacker loop viewer")
    parser.add_argument("--exp-dir", default="attacker/adaptive/results",
                        help="Root directory holding adaptive results")
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    app = build_app(exp_dir=args.exp_dir)
    print(f"Adaptive viewer at http://localhost:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
