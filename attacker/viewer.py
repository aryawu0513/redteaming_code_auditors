"""
attacker/viewer.py — FastAPI backend for the attacker results viewer.

Usage:
    python attacker/viewer.py                           # defaults
    python attacker/viewer.py --port 8080
    python attacker/viewer.py --runs-dir attacker/runs/gpt-5.4-mini

Endpoints:
    GET /api/files            list all verified solutions with metadata
    GET /api/stats            aggregate detection rates per attack type
    GET /api/solution         source code + problem info
    GET /api/repoaudit        RepoAudit log parsed into validation events
    GET /api/vulnllm          VulnLLM-R CoT + prediction for a solution
"""
import argparse
import glob
import json
import re
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

REPO_ROOT = Path(__file__).parent.parent
STATIC_DIR = Path(__file__).parent / "viewer_static"

ATTACK_TYPES = [
    "COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity",
]

# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def _problem_name(repo_dir: Path) -> str:
    pm = repo_dir / "problem.md"
    if pm.exists():
        for line in pm.read_text().splitlines():
            line = line.strip("# ").strip()
            if line:
                return line
    return repo_dir.name


def _scan_runs(runs_dir: Path) -> list[dict]:
    entries = []
    for repo_dir in sorted(runs_dir.glob("repository_*")):
        vpath = repo_dir / "verification.json"
        if not vpath.exists():
            continue
        verif = json.loads(vpath.read_text())
        slug = repo_dir.name.replace("repository_", "")
        problem = _problem_name(repo_dir)
        for at in ATTACK_TYPES:
            status = verif.get(at)
            entries.append({
                "id": f"{slug}/{at}",
                "slug": slug,
                "attack_type": at,
                "problem": problem,
                "verification": status or "missing",
            })
    return entries


def _load_repoaudit_detected(repo_root: Path) -> dict[str, bool]:
    """Map slug/at -> bool (was the bug detected by RepoAudit)."""
    result: dict[str, bool] = {}
    pattern = str(repo_root / "RepoAudit/result/dfbscan/claude-sonnet-4-6/NPD/Cpp/**/detect_info.json")
    for dpath in glob.glob(pattern, recursive=True):
        try:
            data = json.loads(Path(dpath).read_text())
        except Exception:
            continue
        for entry in data.values():
            bv = entry.get("buggy_value", "")
            m = re.search(r"context_aware/(\w+)/(\w+)\.c", bv)
            if m:
                slug, fname = m.group(1), m.group(2)
                at = fname[len(slug) + 1:]
                result[f"{slug}/{at}"] = True
    return result


def _load_vulnllm_results(repo_root: Path) -> dict[str, dict]:
    """Map slug/at -> {flag, predicted, output, cot}."""
    result: dict[str, dict] = {}
    pattern = str(repo_root / "VulnLLM-R/results/C/NPD/attacker/context_aware/*.json")
    for rpath in glob.glob(pattern):
        slug_m = re.search(r"context_aware_([A-F0-9]+)__", rpath)
        if not slug_m:
            continue
        slug = slug_m.group(1)
        ds_dir = repo_root / "VulnLLM-R/datasets/C/NPD/attacker/context_aware" / slug / "c"

        # Build idx -> attack_type from dataset JSONs
        idx_to_at: dict[int, str] = {}
        for ds_file in ds_dir.glob("*.json"):
            try:
                for e in json.loads(ds_file.read_text()):
                    idx_to_at[e["idx"]] = e["attack_type"]
            except Exception:
                pass

        try:
            data = json.loads(Path(rpath).read_text())
        except Exception:
            continue

        for entry in data:
            if "flag" not in entry:
                continue
            at = idx_to_at.get(entry.get("idx"), "")
            if not at:
                continue
            key = f"{slug}/{at}"
            # Prefer most-recent (last in list wins; file is one per slug so no dup slugs)
            result[key] = {
                "flag": entry.get("flag", ""),
                "predicted": entry.get("predicted_is_vulnerable", ""),
                "actual": entry.get("is_vulnerable", ""),
                "output": entry.get("output", ""),
                "cot": entry.get("cot", ""),
            }
    return result


# ---------------------------------------------------------------------------
# RepoAudit log parser
# ---------------------------------------------------------------------------

def _find_repoaudit_log(repo_root: Path, slug: str, at: str) -> Path | None:
    pattern = str(
        repo_root / f"RepoAudit/log/dfbscan/claude-sonnet-4-6/NPD/Cpp/**/{slug}_{at}.log"
    )
    matches = sorted(glob.glob(pattern, recursive=True))
    if not matches:
        return None
    # Pick the most recently modified log
    return max(matches, key=lambda p: Path(p).stat().st_mtime)


def _parse_repoaudit_log(log_path: Path) -> list[dict]:
    """
    Parse a RepoAudit log into a list of path-validation events.
    Each event: {is_reachable, explanation, answer, path_desc}
    """
    try:
        text = log_path.read_text(errors="replace")
    except Exception:
        return []

    events = []
    # Split on the "Output of path_validator:" marker — one block per validated path
    blocks = re.split(r"- INFO - Output of path_validator:\s*\n", text)

    # Preceding-query regex: grab the last propagation-path description before the split
    path_re = re.compile(
        r"does the following data-flow propagation path cause.*?\n((?:\s*- \(.*?\n)+)",
        re.DOTALL,
    )

    for i, block in enumerate(blocks[1:], start=1):
        # Reachable verdict
        reach_m = re.search(r"Is reachable:\s*(True|False)", block)
        is_reachable = reach_m.group(1) == "True" if reach_m else None

        # Explanation (the model's reasoning in this block)
        expl_m = re.search(
            r"Explanation:\s*(.*?)(?:\nAnswer:|\Z)", block, re.DOTALL
        )
        explanation = expl_m.group(1).strip() if expl_m else ""
        # Strip leading "Explanation:" if duplicated
        explanation = re.sub(r"^Explanation:\s*", "", explanation).strip()

        answer_m = re.search(r"\nAnswer:\s*(Yes|No)", block)
        answer = answer_m.group(1) if answer_m else ""

        # Try to extract the path description from the preceding block
        prev_block = blocks[i - 1] if i - 1 < len(blocks) else ""
        path_m = path_re.search(prev_block)
        path_lines = []
        if path_m:
            for line in path_m.group(1).strip().splitlines():
                # Extract just file:line — message from "(msg, file, line, ...)"
                lm = re.search(r"\(([^,]+),\s*[^,]*,\s*(\d+),", line)
                if lm:
                    path_lines.append(f"line {lm.group(2)}: {lm.group(1).strip()}")

        if is_reachable is not None:
            events.append({
                "is_reachable": is_reachable,
                "explanation": explanation,
                "answer": answer,
                "path": " → ".join(path_lines) if path_lines else "",
            })

    return events


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------

def build_app(runs_dir: str, repo_root: str) -> FastAPI:
    runs_path = Path(runs_dir).resolve()
    root_path = Path(repo_root).resolve()
    app = FastAPI(title="Attacker Viewer")

    _cache: dict = {
        "files": None,
        "repoaudit": None,
        "vulnllm": None,
    }

    def _get_data():
        if _cache["files"] is None:
            _cache["files"] = _scan_runs(runs_path)
        if _cache["repoaudit"] is None:
            _cache["repoaudit"] = _load_repoaudit_detected(root_path)
        if _cache["vulnllm"] is None:
            _cache["vulnllm"] = _load_vulnllm_results(root_path)
        return _cache["files"], _cache["repoaudit"], _cache["vulnllm"]

    @app.get("/api/files")
    def list_files(refresh: bool = False):
        if refresh:
            _cache["files"] = _cache["repoaudit"] = _cache["vulnllm"] = None
        files, ra, vl = _get_data()
        enriched = []
        for f in files:
            key = f["id"]
            enriched.append({
                **f,
                "repoaudit_detected": ra.get(key),   # True/None
                "vulnllm_flag": vl.get(key, {}).get("flag"),  # tp/fn/fp/tn/None
            })
        return {"files": enriched}

    @app.get("/api/stats")
    def get_stats():
        files, ra, vl = _get_data()
        # only count ok-verified solutions
        ok = [f for f in files if f["verification"] == "ok"]

        stats = {}
        for at in ATTACK_TYPES:
            subset = [f for f in ok if f["attack_type"] == at]
            n = len(subset)
            ra_det = sum(1 for f in subset if ra.get(f["id"]))
            vl_det = sum(1 for f in subset if vl.get(f["id"], {}).get("flag") == "tp")
            stats[at] = {
                "total": n,
                "repoaudit_detected": ra_det,
                "vulnllm_detected": vl_det,
            }

        total_n = len(ok)
        total_ra = sum(1 for f in ok if ra.get(f["id"]))
        total_vl = sum(1 for f in ok if vl.get(f["id"], {}).get("flag") == "tp")

        return {
            "attack_types": ATTACK_TYPES,
            "per_type": stats,
            "overall": {
                "total": total_n,
                "repoaudit_detected": total_ra,
                "vulnllm_detected": total_vl,
            },
        }

    @app.get("/api/solution")
    def get_solution(slug: str = Query(...), at: str = Query(...)):
        repo_dir = runs_path / f"repository_{slug}"
        if not repo_dir.exists():
            raise HTTPException(404, "Repo not found")
        code_path = repo_dir / f"solution_{at}.c"
        if not code_path.exists():
            raise HTTPException(404, "Solution file not found")

        vpath = repo_dir / "verification.json"
        verif = json.loads(vpath.read_text()) if vpath.exists() else {}

        problem_md = (repo_dir / "problem.md").read_text() if (repo_dir / "problem.md").exists() else ""

        return {
            "slug": slug,
            "attack_type": at,
            "problem": _problem_name(repo_dir),
            "problem_md": problem_md,
            "code": code_path.read_text(),
            "verification": verif.get(at, "missing"),
        }

    @app.get("/api/repoaudit")
    def get_repoaudit(slug: str = Query(...), at: str = Query(...)):
        _, ra, _ = _get_data()
        log_path = _find_repoaudit_log(root_path, slug, at)
        if log_path is None:
            return {"detected": ra.get(f"{slug}/{at}"), "validations": [], "log_found": False}
        events = _parse_repoaudit_log(log_path)
        return {
            "detected": ra.get(f"{slug}/{at}", False),
            "validations": events,
            "log_found": True,
            "log_path": str(log_path.relative_to(root_path)),
        }

    @app.get("/api/vulnllm")
    def get_vulnllm(slug: str = Query(...), at: str = Query(...)):
        _, _, vl = _get_data()
        key = f"{slug}/{at}"
        data = vl.get(key)
        if data is None:
            return {"available": False}
        return {"available": True, **data}

    # Serve frontend
    if STATIC_DIR.exists():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Attacker results viewer")
    parser.add_argument("--runs-dir",
                        default=str(REPO_ROOT / "attacker/runs/gpt-5.4-mini"),
                        help="Directory containing repository_* subdirs")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--port", type=int, default=7801)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    app = build_app(runs_dir=args.runs_dir, repo_root=args.repo_root)
    print(f"Attacker viewer → http://localhost:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
