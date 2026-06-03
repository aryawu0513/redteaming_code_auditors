"""
viewer.py — CVE candidate viewer with VulnLLM-R verdict overlay.

Usage:
    # Show all filter-3 survivors + verdicts (auto-merges f3_retry.results.jsonl):
    python viewer.py --jsonl f3_dedup.jsonl --results f3_dedup.results.jsonl

    # Explicitly merge a second results file:
    python viewer.py --jsonl f3_dedup.jsonl --results f3_dedup.results.jsonl --results2 f3_retry.results.jsonl

    # Show only confirmed candidates (post VulnLLM-R):
    python viewer.py --candidates-dir candidates/

    # Show filter-3 survivors without verdicts:
    python viewer.py --jsonl f3_dedup.jsonl
"""

import argparse
import difflib
import json
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles

HERE = Path(__file__).parent
STATIC_DIR = HERE / "viewer_static"
DEFAULT_CANDIDATES = HERE / "candidates"


def _find_func_line(full_file: str, func_name: str) -> int | None:
    if not func_name:
        return None
    for i, line in enumerate(full_file.splitlines(), 1):
        if func_name in line and "(" in line:
            return i
    return None


def _make_diff(before: str, after: str) -> list[dict]:
    a = (before or "").splitlines()
    b = (after  or "").splitlines()
    result = []
    for group in difflib.SequenceMatcher(None, a, b).get_grouped_opcodes(3):
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for line in a[i1:i2]:
                    result.append({"type": "ctx", "line": line})
            if tag in ("replace", "delete"):
                for line in a[i1:i2]:
                    result.append({"type": "del", "line": line})
            if tag in ("replace", "insert"):
                for line in b[j1:j2]:
                    result.append({"type": "add", "line": line})
    return result


def _normalize(raw: dict, verdict_info: dict | None) -> dict:
    suffix = Path(raw.get("file_path", "")).suffix.lower()
    lang = "cpp" if suffix in (".cpp", ".cc", ".cxx") else "c"
    full_file = raw.get("full_file", "")
    func_name = raw.get("func_name", "")
    commit    = raw.get("commit_hash", "")
    repo      = raw.get("repo_url", "")
    vuln  = raw.get("vulnerable_code", "")
    fixed = raw.get("_fixed_code", "") or raw.get("fixed_code", "")

    verdict   = verdict_info.get("verdict",   "unknown") if verdict_info else "unknown"
    reasoning = verdict_info.get("reasoning", "")        if verdict_info else ""
    heuristic   = verdict_info.get("heuristic",   None)  if verdict_info else None
    diff_ptrs   = verdict_info.get("diff_ptrs",   [])    if verdict_info else []
    mentioned   = verdict_info.get("mentioned",   [])    if verdict_info else []
    unmentioned = verdict_info.get("unmentioned", [])    if verdict_info else []

    return {
        "cve_id":          raw.get("cve_id", ""),
        "func_name":       func_name,
        "file_path":       raw.get("file_path", ""),
        "repo_url":        repo,
        "commit_hash":     commit,
        "commit_message":  raw.get("commit_message", ""),
        "source":          raw.get("source", ""),
        "lang":            lang,
        "vulnerable_code": vuln,
        "fixed_code":      fixed,
        "diff":            _make_diff(vuln, fixed) if vuln and fixed else [],
        "full_file":       full_file,
        "full_file_lines": len(full_file.splitlines()) if full_file else 0,
        "func_line":       _find_func_line(full_file, func_name),
        "lines_added":     raw.get("_lines_added"),
        "commit_url":      f"{repo}/commit/{commit}" if repo and commit else None,
        "nvd_url":         f"https://nvd.nist.gov/vuln/detail/{raw['cve_id']}"
                           if raw.get("cve_id") else None,
        # VulnLLM-R
        "verdict":         verdict,
        "reasoning":       reasoning,
        # Filter 5 heuristic
        "heuristic":       heuristic,
        "diff_ptrs":       diff_ptrs,
        "mentioned":       mentioned,
        "unmentioned":     unmentioned,
    }


def _load_results(results_path: Path | None, extra_path: Path | None = None) -> dict:
    """Load results JSONL → dict keyed by (cve_id, func_name). Merges extra_path on top."""
    out = {}
    for p in [results_path, extra_path]:
        if not p or not p.exists():
            continue
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                key = (r.get("cve_id", ""), r.get("func_name", ""))
                out[key] = r
            except Exception:
                pass
    return out


def build_app(data_source: Path, results_path: Path | None, extra_results: Path | None = None) -> FastAPI:
    results = _load_results(results_path, extra_results)
    has_results = bool(results)

    # Load records
    records: dict[str, dict] = {}

    if data_source.suffix == ".jsonl":
        for line in data_source.read_text().splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            key   = (raw.get("cve_id", ""), raw.get("func_name", ""))
            vinfo = results.get(key)
            r     = _normalize(raw, vinfo)
            rid   = f"{r['cve_id']}_{Path(r['file_path']).stem}_{r['func_name']}"
            records[rid] = r
    else:
        # candidates/ directory — no results overlay (already filtered)
        for f in sorted(data_source.glob("*.json")):
            try:
                raw = json.loads(f.read_text())
                key = (raw.get("cve_id", ""), raw.get("func_name", ""))
                r   = _normalize(raw, results.get(key))
                records[f.stem] = r
            except Exception:
                pass

    app = FastAPI(title="CVE Candidate Viewer")

    @app.get("/api/candidates")
    def list_candidates():
        return [
            {
                "id":          id_,
                "cve_id":      r["cve_id"],
                "func_name":   r["func_name"],
                "file_path":   r["file_path"],
                "lang":        r["lang"],
                "lines_added": r.get("lines_added"),
                "verdict":     r["verdict"],
                "heuristic":   r.get("heuristic"),
                "has_diff":    bool(r["diff"]),
            }
            for id_, r in records.items()
        ]

    @app.get("/api/candidate")
    def get_candidate(id: str = Query(...)):
        if id not in records:
            raise HTTPException(404, f"{id!r} not found")
        return {"id": id, **records[id]}

    @app.get("/api/meta")
    def meta():
        counts = {}
        for r in records.values():
            v = r["verdict"]
            counts[v] = counts.get(v, 0) + 1
        return {"has_results": has_results, "total": len(records), "counts": counts}

    if STATIC_DIR.exists():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8082)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--jsonl", default=None)
    ap.add_argument("--results", default=None,
                    help="VulnLLM-R results JSONL to overlay on --jsonl")
    ap.add_argument("--results2", default=None,
                    help="Second results JSONL merged on top (e.g. retry results)")
    ap.add_argument("--candidates-dir", default=str(DEFAULT_CANDIDATES))
    args = ap.parse_args()

    if args.jsonl:
        src = Path(args.jsonl)
        res = Path(args.results) if args.results else src.with_suffix(".results.jsonl")
        if not res.exists():
            res = None
        # Auto-detect sibling results files (retry, f5 heuristic)
        res2: Path | None = None
        if args.results2:
            res2 = Path(args.results2)
        else:
            stem = src.stem  # e.g. "f3_dedup"
            prefix = stem.split("_")[0]  # e.g. "f3"
            retry_candidate = src.parent / f"{prefix}_retry.results.jsonl"
            if retry_candidate.exists() and retry_candidate != res:
                res2 = retry_candidate

        # Auto-detect f5 heuristic results (stem.f5.jsonl) and prefer over plain results
        f5_candidate = src.parent / f"{src.stem}.f5.jsonl"
        if f5_candidate.exists():
            res = f5_candidate
            res2 = None  # f5 already contains all results + heuristic fields
    else:
        src = Path(args.candidates_dir)
        res = None
        res2 = None

    if not src.exists():
        print(f"ERROR: not found: {src}", file=sys.stderr)
        sys.exit(1)

    app = build_app(src, res, res2)
    verdict_note = f" + {res}" if res else ""
    if res2:
        verdict_note += f" + {res2.name}"
    print(f"Viewer at http://localhost:{args.port}  ({src}{verdict_note})")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
