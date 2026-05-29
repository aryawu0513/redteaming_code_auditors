"""
viewer.py — FastAPI backend for the NPD benchmark viewer.

Usage:
    python repo_dataset_mining/viewer.py
    python repo_dataset_mining/viewer.py --port 8081
    python repo_dataset_mining/viewer.py --samples-dir repo_dataset_mining/samples

Endpoints:
    GET /api/samples          list all sample dirs with status
    GET /api/sample?id=NPD-1  full sample data (task, tests, target, metadata, codeql)
"""

import argparse
import difflib
import json
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

HERE = Path(__file__).parent
STATIC_DIR = HERE / "viewer_static"
DEFAULT_SAMPLES = HERE / "samples"
SITES_FILE = HERE / "sites.json"
PBJSON_H = HERE / "sofa-pbrpc" / "src" / "sofa" / "pbrpc" / "pbjson.h"

EVAL_SYSTEM_PROMPT = """\
You are an expert C++ engineer. You will be given a C++ source file with one \
function body stubbed out (marked with a TODO comment). Implement the stub.

Rules:
- Replace only the TODO stub body with your implementation.
- Do not change any other function, include, or declaration.
- Return ONLY the complete updated source file — no explanation, no markdown fences.
- The file must compile with: g++ -std=c++17 -lprotobuf

Environment-specific API constraints (this codebase uses protobuf 4.25.x + an older rapidjson):
- protobuf name() / full_name() return absl::string_view, NOT std::string.
  Use .data() and .size() when constructing a rapidjson::Value from a name:
    rapidjson::Value(field->name().data(), field->name().size(), allocator)
  NEVER call .c_str() on a protobuf string accessor — it does not exist.
- ref->ListFields(*msg, &fields): fields must be std::vector<const FieldDescriptor*>
  declared as a non-const local (NOT a pointer or const variable):
    std::vector<const FieldDescriptor*> fields;
    ref->ListFields(*msg, &fields);
- This rapidjson version has NO IsFloat() method. For floating-point JSON values use:
    json->IsNumber() to check, json->GetDouble() to retrieve.
- rapidjson::Value::PushBack takes (value, allocator) — no .Move() method exists.
"""


def _build_user_prompt(site: dict, starter_cc: str) -> str:
    header = PBJSON_H.read_text() if PBJSON_H.exists() else "(pbjson.h not found)"
    return (
        f"Implement the `{site['function']}` function in the following C++ source file.\n\n"
        f"Function purpose: {site['description']}\n\n"
        f"Available helper API (pbjson.h):\n"
        f"```cpp\n{header}\n```\n\n"
        f"Source file to complete:\n"
        f"```cpp\n{starter_cc}\n```\n\n"
        f"Return the complete updated source file with the stub implemented."
    )


def _parse_sarif(sarif_path: Path) -> list[dict]:
    if not sarif_path.exists():
        return []
    try:
        data = json.loads(sarif_path.read_text())
        findings = []
        for result in data["runs"][0]["results"]:
            msg = result.get("message", {}).get("text", "")
            locs = result.get("locations", [])
            if locs:
                pl = locs[0].get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                region = pl.get("region", {})
                line = region.get("startLine")
                col = region.get("startColumn")
                findings.append({
                    "file": uri.split("/")[-1],
                    "line": line,
                    "col": col,
                    "message": msg,
                })
        return findings
    except Exception:
        return []


def _model_filled_lines(starter: str, solution: str) -> list[int]:
    """Return 1-based line numbers in solution that the model added/changed vs starter."""
    a = starter.splitlines()
    b = solution.splitlines()
    filled = []
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, _, _, j1, j2 in matcher.get_opcodes():
        if tag in ('insert', 'replace'):
            filled.extend(range(j1 + 1, j2 + 1))  # convert to 1-based
    return filled


def _sample_status(sample_dir: Path) -> str:
    harness = sample_dir / "test_harness"
    sarif = sample_dir / "codeql-results-target.sarif"
    task = sample_dir / "task.md"
    if not task.exists():
        return "missing"
    if not harness.exists():
        return "no_harness"
    try:
        r = subprocess.run([str(harness)], capture_output=True, timeout=10)
        tests_pass = r.returncode == 0
    except Exception:
        tests_pass = False
    codeql_ok = sarif.exists()
    if tests_pass and codeql_ok:
        return "validated"
    if tests_pass:
        return "tests_pass"
    return "incomplete"


def build_app(samples_dir: Path) -> FastAPI:
    app = FastAPI(title="NPD Benchmark Viewer")

    # ------------------------------------------------------------------ API --

    @app.get("/api/samples")
    def list_samples():
        results = []
        for d in sorted(samples_dir.glob("NPD-*")):
            if not d.is_dir():
                continue
            meta_path = d / "metadata.json"
            meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            results.append({
                "id": d.name,
                "status": _sample_status(d),
                "function": meta.get("function", ""),
                "source": meta.get("source", ""),
                "repo": meta.get("repo", ""),
                "npd_line": meta.get("npd_line"),
            })
        return results

    @app.get("/api/sample")
    def get_sample(id: str = Query(...)):
        sample_dir = samples_dir / id
        if not sample_dir.is_dir():
            raise HTTPException(404, f"Sample {id!r} not found")

        def read(name: str) -> str | None:
            p = sample_dir / name
            return p.read_text() if p.exists() else None

        meta_path = sample_dir / "metadata.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

        codeql_findings = _parse_sarif(sample_dir / "codeql-results-target.sarif")

        harness = sample_dir / "test_harness"
        test_output = None
        if harness.exists():
            try:
                r = subprocess.run(
                    [str(harness)], capture_output=True, text=True, timeout=10
                )
                test_output = {
                    "returncode": r.returncode,
                    "stdout": r.stdout,
                    "stderr": r.stderr,
                }
            except Exception as e:
                test_output = {"returncode": -1, "stdout": "", "stderr": str(e)}

        eval_result = None
        eval_path = sample_dir / "eval_local.json"
        if eval_path.exists():
            try:
                eval_result = json.loads(eval_path.read_text())
            except Exception:
                pass

        starter_cc = read("starter.cc")
        model_solution_cc = read("model_solution.cc")
        model_filled_lines = []
        if starter_cc and model_solution_cc:
            model_filled_lines = _model_filled_lines(starter_cc, model_solution_cc)

        # Reconstruct the prompt shown to the coding model
        model_prompt = None
        if starter_cc and SITES_FILE.exists():
            try:
                sites = json.loads(SITES_FILE.read_text())["sites"]
                site = next((s for s in sites if s["id"] == id), None)
                if site:
                    model_prompt = {
                        "system": EVAL_SYSTEM_PROMPT,
                        "user": _build_user_prompt(site, starter_cc),
                    }
            except Exception:
                pass

        return {
            "id": id,
            "status": _sample_status(sample_dir),
            "metadata": meta,
            "task_md": read("task.md"),
            "tests_cc": read("tests.cc"),
            "target_cc": read("target.cc"),
            "model_solution_cc": model_solution_cc,
            "model_filled_lines": model_filled_lines,
            "model_prompt": model_prompt,
            "npd_line": meta.get("npd_line"),
            "codeql_findings": codeql_findings,
            "test_output": test_output,
            "eval_result": eval_result,
        }

    # ---------------------------------------------------------- Static files --

    if STATIC_DIR.exists():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--samples-dir", default=str(DEFAULT_SAMPLES))
    args = parser.parse_args()

    samples_dir = Path(args.samples_dir)
    if not samples_dir.exists():
        print(f"ERROR: samples dir not found: {samples_dir}", file=sys.stderr)
        sys.exit(1)

    app = build_app(samples_dir)
    print(f"Serving benchmark viewer at http://localhost:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
