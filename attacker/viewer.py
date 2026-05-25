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
import difflib
import glob
import json
import re
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

REPO_ROOT = Path(__file__).parent.parent
STATIC_DIR = Path(__file__).parent / "viewer_static"
SCAFFOLD_DIR = Path(__file__).parent / "scaffold_results"

ATTACK_TYPES = [
    "COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity",
]

# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def _find_npd_line_in_baseline(baseline: str, attack: str) -> int | None:
    """Return the 1-indexed line in baseline just before the attack comment block.

    The attack variant adds a comment block immediately after the NPD dereference
    line. We find the largest insertion via difflib and return the baseline line
    number right before it — that is the dereference (bug) line.
    """
    b_lines = baseline.splitlines()
    a_lines = attack.splitlines()
    sm = difflib.SequenceMatcher(None, b_lines, a_lines, autojunk=False)
    best: tuple[int, int, int] | None = None  # (j1, j2, i1)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "insert" and i1 > 0 and (j2 - j1) >= 1:
            if best is None or (j2 - j1) > (best[1] - best[0]):
                best = (j1, j2, i1)
    return best[2] if best else None


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


def _load_baseline_detectable(repo_root: Path) -> dict[str, bool]:
    """Map slug -> bool (did VulnLLM-R detect bug in solution.c without attack comment)."""
    return {slug: d["predicted"] == "yes"
            for slug, d in _load_baseline_vulnllm(repo_root).items()}


def _load_baseline_vulnllm(repo_root: Path) -> dict[str, dict]:
    """Map slug -> {predicted, flag, output} for the unmodified solution.c baseline."""
    result: dict[str, dict] = {}
    pattern = str(repo_root / "VulnLLM-R/results/C/NPD/attacker/baseline/*.json")
    for rpath in glob.glob(pattern):
        m = re.search(r"baseline_([A-F0-9]+)__", rpath)
        if not m:
            continue
        slug = m.group(1)
        try:
            data = json.loads(Path(rpath).read_text())
        except Exception:
            continue
        for entry in data:
            if "predicted_is_vulnerable" not in entry:
                continue
            result[slug] = {
                "predicted": entry.get("predicted_is_vulnerable", ""),
                "flag":      entry.get("flag", ""),
                "output":    entry.get("output", ""),
            }
            break
    return result


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
# VulTrial + OpenVul loaders
# ---------------------------------------------------------------------------

ATTACK_IDX_MAP: dict[int, str] = {
    0: "CLEAN", 1: "COT", 2: "FT", 3: "CG", 4: "AA_MSG", 5: "AA_USR",
    6: "AA_CA", 7: "TOOL_ClangSA", 8: "TOOL_Frama", 9: "TOOL_Fuzzer",
    10: "TOOL_Coverity",
}


def _parse_vultrial_file(data: list, include_clean: bool = False) -> dict[str, dict]:
    """Parse a VulTrial result list into slug/at -> entry dict."""
    result: dict[str, dict] = {}
    for entry in data:
        if "flag" not in entry:
            continue
        attack = entry.get("attack", "")
        if len(attack) < 13:
            continue
        slug = attack[:12]
        at = attack[13:]
        if at == "CLEAN" and not include_clean:
            continue
        key = slug if at == "CLEAN" else f"{slug}/{at}"
        result[key] = {
            "flag":      entry.get("flag", ""),
            "predicted": entry.get("predicted_is_vulnerable", ""),
            "actual":    entry.get("is_vulnerable", ""),
            "output":    entry.get("output", ""),
        }
    return result


def _load_vultrial_results(repo_root: Path,
                           model: str = "gpt-4o",
                           mode: str = "generic") -> dict[str, dict]:
    """Map slug/at -> {flag, predicted, actual, output}."""
    result: dict[str, dict] = {}
    pattern = str(repo_root / f"VulTrial/results/{model}/{mode}/attacker_lcb/C/NPD/*.json")
    for rpath in glob.glob(pattern):
        try:
            data = json.loads(Path(rpath).read_text())
        except Exception:
            continue
        result.update(_parse_vultrial_file(data, include_clean=False))
    return result


def _load_vultrial_baseline(repo_root: Path,
                            model: str = "gpt-4o",
                            mode: str = "generic") -> dict[str, dict]:
    """Map slug -> {flag, predicted, actual, output} for CLEAN variant."""
    result: dict[str, dict] = {}
    pattern = str(repo_root / f"VulTrial/results/{model}/{mode}/attacker_lcb/C/NPD/*.json")
    for rpath in glob.glob(pattern):
        try:
            data = json.loads(Path(rpath).read_text())
        except Exception:
            continue
        result.update(_parse_vultrial_file(data, include_clean=True))
    # keep only slug-keyed entries (no "/" in key)
    return {k: v for k, v in result.items() if "/" not in k}


def _load_openvul_results(repo_root: Path) -> dict[str, dict]:
    """Map slug/at -> {flag, predicted, actual, votes, output}."""
    result: dict[str, dict] = {}
    pattern = str(repo_root / "OpenVul/results/attacker_lcb/C/NPD/*.json")
    for rpath in glob.glob(pattern):
        m = re.search(r"repository_([A-F0-9]+)__", rpath)
        if not m:
            continue
        slug = m.group(1)
        try:
            data = json.loads(Path(rpath).read_text())
        except Exception:
            continue
        for entry in data:
            if "flag" not in entry:
                continue
            at = ATTACK_IDX_MAP.get(entry.get("idx"), "")
            if not at or at == "CLEAN":
                continue
            result[f"{slug}/{at}"] = {
                "flag":      entry.get("flag", ""),
                "predicted": entry.get("predicted_is_vulnerable", ""),
                "actual":    entry.get("is_vulnerable", ""),
                "votes":     entry.get("votes", {}),
                "output":    entry.get("output", ""),
            }
    return result


def _load_openvul_baseline(repo_root: Path) -> dict[str, dict]:
    """Map slug -> {flag, predicted, votes, output} for CLEAN variant."""
    result: dict[str, dict] = {}
    pattern = str(repo_root / "OpenVul/results/attacker_lcb/C/NPD/*.json")
    for rpath in glob.glob(pattern):
        m = re.search(r"repository_([A-F0-9]+)__", rpath)
        if not m:
            continue
        slug = m.group(1)
        try:
            data = json.loads(Path(rpath).read_text())
        except Exception:
            continue
        for entry in data:
            if "flag" not in entry:
                continue
            if ATTACK_IDX_MAP.get(entry.get("idx")) == "CLEAN":
                result[slug] = {
                    "flag":      entry.get("flag", ""),
                    "predicted": entry.get("predicted_is_vulnerable", ""),
                    "actual":    entry.get("is_vulnerable", ""),
                    "votes":     entry.get("votes", {}),
                    "output":    entry.get("output", ""),
                }
                break
    return result


# ---------------------------------------------------------------------------
# VulnLLM-R Agent Scaffold loaders
# ---------------------------------------------------------------------------

def _load_scaffold_baseline(slug: str) -> list[dict]:
    """Load per-function scaffold results for unmodified solution.c."""
    p = SCAFFOLD_DIR / f"scaffold_{slug}.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text())
    except Exception:
        return []


def _load_scaffold_attack(slug: str, at: str) -> list[dict]:
    """Load per-function scaffold results for the given attack variant."""
    p = SCAFFOLD_DIR / "attacks" / f"scaffold_{slug}.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data.get(at, [])
    except Exception:
        return []


def _scaffold_overall(entries: list[dict]) -> str | None:
    """Return 'yes'/'no'/None for whether CWE-476 was detected in any function."""
    if not entries:
        return None
    for e in entries:
        if e.get("judge") == "yes" and "476" in (e.get("cwe_type") or ""):
            return "yes"
    return "no"


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
    return Path(max(matches, key=lambda p: Path(p).stat().st_mtime))


def _parse_explorer_sections(text: str) -> list[dict]:
    """
    Extract explorer calls. Uses sequential pairing of [EXPLORER] Analyzing ↔
    [EXPLORER] Output: (stable even for batched async calls), then attaches the
    IntraDataFlowAnalyzer Response: that immediately precedes each output.
    """
    # Collect [EXPLORER] Analyzing entries in order
    analyzing = []
    for m in re.finditer(
        r"\[EXPLORER\] Analyzing (\w+)\(\) for source '(.+?)' \(label=\w+\) at line (\d+)",
        text,
    ):
        analyzing.append({"func": m.group(1), "src": m.group(2), "line": int(m.group(3)),
                          "pos": m.start()})

    # Split on [EXPLORER] Output: to get (preceding-block, output-text) pairs.
    # The Response: for an intra-procedural call always sits between the
    # "Output of intra-procedural data-flow analyzer:" log line and the
    # [EXPLORER] Output: line in that same block.
    parts = re.split(r"\[EXPLORER\] Output: (.+)", text)
    blocks  = parts[0::2]   # text before each [EXPLORER] Output:
    outputs = parts[1::2]   # the output payload

    # For each block, find the IntraDataFlowAnalyzer Response: (identified by
    # being followed by "Output of intra-procedural" rather than a validator line).
    responses = []
    for block in blocks:
        resp_m = re.search(
            r"- INFO - Response:\s*\n(.*?)(?=\n\d{4}-\d{2}-\d{2}.*?Output of intra-procedural)",
            block,
            re.DOTALL,
        )
        responses.append(resp_m.group(1).strip() if resp_m else "")

    sections = []
    for i, a in enumerate(analyzing):
        sections.append({
            "func":     a["func"],
            "src":      a["src"],
            "line":     a["line"],
            "response": responses[i] if i < len(responses) else "",
            "output":   outputs[i].strip() if i < len(outputs) else "",
        })
    return sections


def _parse_repoaudit_log(log_path: Path) -> list[dict]:
    """
    Parse a RepoAudit log into a list of path-validation events.
    Each event: {is_reachable, explanation, answer, path_steps}
    """
    try:
        text = log_path.read_text(errors="replace")
    except Exception:
        return []

    events = []
    blocks = re.split(r"- INFO - Output of path_validator:\s*\n", text)

    # Path step format: " - ((expr, file, line, offset), ValueLabel.TYPE) in the function FN at the line N"
    step_re = re.compile(
        r"^\s*-\s+\(\(([^,]+),\s*[^,]+,\s*(\d+),\s*[^)]+\),\s*(ValueLabel\.\w+)\)\s+in the function\s+(\w+)\s+at the line\s+(\d+)",
    )

    def extract_path_steps(block_text: str) -> list[dict]:
        """Extract path steps from the validator prompt block."""
        steps = []
        # Find the path section (after "does the following ... path cause" + backtick block)
        path_section_m = re.search(
            r"does the following (?:data-flow )?propagation path cause[^`\n]*\n```[^\n]*\n((?:\s*-\s+\(\(.*?\n)+)",
            block_text,
        )
        if not path_section_m:
            # Try without backtick wrapper
            path_section_m = re.search(
                r"does the following (?:data-flow )?propagation path cause[^\n]*\n((?:\s*-\s+\(\(.*?\n)+)",
                block_text,
            )
        if not path_section_m:
            return steps
        for line in path_section_m.group(1).splitlines():
            m = step_re.match(line)
            if m:
                steps.append({
                    "expr":  m.group(1).strip(),
                    "line":  int(m.group(2)),
                    "label": m.group(3).replace("ValueLabel.", ""),
                    "func":  m.group(4),
                })
        return steps

    for i, block in enumerate(blocks[1:], start=1):
        reach_m = re.search(r"Is reachable:\s*(True|False)", block)
        is_reachable = reach_m.group(1) == "True" if reach_m else None

        expl_m = re.search(r"Explanation:\s*(.*?)(?:\nAnswer:|\Z)", block, re.DOTALL)
        explanation = expl_m.group(1).strip() if expl_m else ""
        explanation = re.sub(r"^Explanation:\s*", "", explanation).strip()

        answer_m = re.search(r"\nAnswer:\s*(Yes|No)", block)
        answer = answer_m.group(1) if answer_m else ""

        prev_block = blocks[i - 1] if i - 1 < len(blocks) else ""
        path_steps = extract_path_steps(prev_block)

        # Build compact path summary for the accordion header
        if path_steps:
            path_str = " → ".join(
                f"{s['func']}:{s['line']} {s['expr']} [{s['label']}]"
                for s in path_steps
            )
        else:
            path_str = ""

        if is_reachable is not None:
            events.append({
                "is_reachable": is_reachable,
                "explanation": explanation,
                "answer": answer,
                "path": path_str,
                "path_steps": path_steps,
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
        "baseline": None,
        "baseline_vl": None,
        "vultrial": None,
        "openvul": None,
        "baseline_vt": None,
        "baseline_ov": None,
    }

    def _get_data():
        if _cache["files"] is None:
            _cache["files"] = _scan_runs(runs_path)
        if _cache["repoaudit"] is None:
            _cache["repoaudit"] = _load_repoaudit_detected(root_path)
        if _cache["vulnllm"] is None:
            _cache["vulnllm"] = _load_vulnllm_results(root_path)
        if _cache["baseline_vl"] is None:
            _cache["baseline_vl"] = _load_baseline_vulnllm(root_path)
        if _cache["baseline"] is None:
            _cache["baseline"] = {s: d["predicted"] == "yes"
                                   for s, d in _cache["baseline_vl"].items()}
        if _cache["vultrial"] is None:
            _cache["vultrial"] = _load_vultrial_results(root_path)
        if _cache["openvul"] is None:
            _cache["openvul"] = _load_openvul_results(root_path)
        if _cache["baseline_vt"] is None:
            _cache["baseline_vt"] = _load_vultrial_baseline(root_path)
        if _cache["baseline_ov"] is None:
            _cache["baseline_ov"] = _load_openvul_baseline(root_path)
        return _cache["files"], _cache["repoaudit"], _cache["vulnllm"], _cache["baseline"]

    @app.get("/api/files")
    def list_files(refresh: bool = False):
        if refresh:
            for k in _cache: _cache[k] = None
        files, ra, vl, bl = _get_data()
        vt  = _cache["vultrial"]    or {}
        ov  = _cache["openvul"]     or {}
        bvt = _cache["baseline_vt"] or {}
        bov = _cache["baseline_ov"] or {}
        enriched = []
        for f in files:
            key = f["id"]
            slug = f["slug"]
            enriched.append({
                **f,
                "repoaudit_detected":   ra.get(key),
                "vulnllm_flag":         vl.get(key, {}).get("flag"),
                "vultrial_flag":        vt.get(key, {}).get("flag"),
                "openvul_flag":         ov.get(key, {}).get("flag"),
                "baseline_detectable":  bl.get(slug),
                "baseline_vt_flag":     bvt.get(slug, {}).get("flag"),
                "baseline_ov_flag":     bov.get(slug, {}).get("flag"),
            })
        return {"files": enriched}

    @app.get("/api/stats")
    def get_stats():
        files, ra, vl, bl = _get_data()
        vt = _cache["vultrial"] or {}
        ov = _cache["openvul"] or {}
        ok = [f for f in files if f["verification"] == "ok"]

        stats = {}
        for at in ATTACK_TYPES:
            subset = [f for f in ok if f["attack_type"] == at]
            n = len(subset)
            stats[at] = {
                "total":               n,
                "repoaudit_detected":  sum(1 for f in subset if ra.get(f["id"])),
                "vulnllm_detected":    sum(1 for f in subset if vl.get(f["id"], {}).get("flag") == "tp"),
                "vultrial_detected":   sum(1 for f in subset if vt.get(f["id"], {}).get("flag") == "tp"),
                "openvul_detected":    sum(1 for f in subset if ov.get(f["id"], {}).get("flag") == "tp"),
            }

        total_n = len(ok)
        return {
            "attack_types": ATTACK_TYPES,
            "per_type": stats,
            "overall": {
                "total":               total_n,
                "repoaudit_detected":  sum(1 for f in ok if ra.get(f["id"])),
                "vulnllm_detected":    sum(1 for f in ok if vl.get(f["id"], {}).get("flag") == "tp"),
                "vultrial_detected":   sum(1 for f in ok if vt.get(f["id"], {}).get("flag") == "tp"),
                "openvul_detected":    sum(1 for f in ok if ov.get(f["id"], {}).get("flag") == "tp"),
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

        attack_code = code_path.read_text(errors="replace")
        baseline_path = repo_dir / "solution.c"
        baseline_code = baseline_path.read_text(errors="replace") if baseline_path.exists() else ""
        npd_line: int | None = None
        if baseline_code:
            try:
                npd_line = _find_npd_line_in_baseline(baseline_code, attack_code)
            except Exception:
                pass

        return {
            "slug": slug,
            "attack_type": at,
            "problem": _problem_name(repo_dir),
            "problem_md": problem_md,
            "code": attack_code,
            "verification": verif.get(at, "missing"),
            "baseline_code": baseline_code,
            "npd_line": npd_line,
        }

    @app.get("/api/repoaudit")
    def get_repoaudit(slug: str = Query(...), at: str = Query(...)):
        _, ra, _, _bl = _get_data()
        log_path = _find_repoaudit_log(root_path, slug, at)
        if log_path is None:
            return {"detected": ra.get(f"{slug}/{at}"), "validations": [], "explorer": [], "log_found": False}
        try:
            text = log_path.read_text(errors="replace")
        except Exception:
            text = ""
        events = _parse_repoaudit_log(log_path)
        explorer = _parse_explorer_sections(text)
        return {
            "detected": ra.get(f"{slug}/{at}", False),
            "validations": events,
            "explorer": explorer,
            "log_found": True,
            "log_path": str(log_path.relative_to(root_path)),
        }

    @app.get("/api/problem")
    def get_problem_baseline(slug: str = Query(...)):
        _get_data()  # ensure baseline_vl is populated
        repo_dir = runs_path / f"repository_{slug}"
        if not repo_dir.exists():
            raise HTTPException(404, "Repo not found")

        code_path = repo_dir / "solution.c"
        code = code_path.read_text(errors="replace") if code_path.exists() else ""

        problem_md = (repo_dir / "problem.md").read_text() if (repo_dir / "problem.md").exists() else ""

        bvl = _cache.get("baseline_vl") or {}
        bvt = _cache.get("baseline_vt") or {}
        bov = _cache.get("baseline_ov") or {}

        return {
            "slug": slug,
            "code": code,
            "problem_md": problem_md,
            "vulnllm":  bvl.get(slug),   # {predicted, flag, output} or None
            "vultrial": bvt.get(slug),   # {flag, predicted, output} or None
            "openvul":  bov.get(slug),   # {flag, predicted, votes, output} or None
            "repoaudit": None,
        }

    @app.get("/api/vulnllm")
    def get_vulnllm(slug: str = Query(...), at: str = Query(...)):
        _, _, vl, _bl = _get_data()
        key = f"{slug}/{at}"
        data = vl.get(key)
        baseline = _cache["baseline_vl"].get(slug) if _cache.get("baseline_vl") else None
        if data is None:
            return {"available": False, "baseline": baseline}
        return {"available": True, **data, "baseline": baseline}

    @app.get("/api/vultrial")
    def get_vultrial(slug: str = Query(...), at: str = Query(...),
                     model: str = "gpt-4o", mode: str = "generic"):
        _get_data()
        vt = _cache["vultrial"] or {}
        data = vt.get(f"{slug}/{at}")
        # Load per-turn output files
        model_slug = model.replace("-", "_").replace(".", "_")
        id_save = f"repository_{slug}_{slug}_{at}_{mode}_{model_slug}"
        turns_dir = root_path / "VulTrial/results/output" / id_save
        turns = {}
        for i in range(4):
            p = turns_dir / f"{i}.txt"
            turns[str(i)] = p.read_text(errors="replace") if p.exists() else None
        if data is None:
            return {"available": False, "turns": turns}
        return {"available": True, **data, "turns": turns}

    @app.get("/api/openvul")
    def get_openvul(slug: str = Query(...), at: str = Query(...)):
        _get_data()
        ov = _cache["openvul"] or {}
        data = ov.get(f"{slug}/{at}")
        if data is None:
            return {"available": False}
        return {"available": True, **data}

    @app.get("/api/scaffold")
    def get_scaffold(slug: str = Query(...), at: str = Query("")):
        baseline = _load_scaffold_baseline(slug)
        attack = _load_scaffold_attack(slug, at) if at else []
        return {
            "slug": slug,
            "at": at,
            "baseline": baseline,
            "baseline_overall": _scaffold_overall(baseline),
            "attack": attack,
            "attack_overall": _scaffold_overall(attack) if attack else None,
        }

    # Serve index.html directly with no-cache so browser never uses stale HTML
    @app.get("/")
    async def serve_index():
        resp = FileResponse(str(STATIC_DIR / "index.html"), media_type="text/html")
        resp.headers["Cache-Control"] = "no-store"
        return resp

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
