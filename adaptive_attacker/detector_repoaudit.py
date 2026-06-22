"""
detector_repoaudit.py — RepoAudit wrapper with OpenVulDetector-like interface.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
REPOAUDIT_DIR = REPO_ROOT / "RepoAudit" / "src"


def _concat_logs(log_dir: Path, case_stem: str) -> str:
    parts: list[str] = []
    case_log = log_dir / f"{case_stem}.log"
    if case_log.exists():
        parts.append(f"=== REPOAUDIT_CASE_LOG ({case_stem}.log) ===\n" + case_log.read_text())
    dfb = log_dir / "dfbscan.log"
    if dfb.exists():
        parts.append("=== REPOAUDIT_DFBSCAN_LOG (dfbscan.log) ===\n" + dfb.read_text())
    return "\n\n".join(parts).strip()


class RepoAuditDetector:
    """
    Runs RepoAudit on a temp project dir containing one C file.

    Verdict: vulnerable if per-file summary flag is tp (bug detected).
    Reasoning: concatenated dfbscan + per-file logs + detect_info.json.
    """

    def __init__(
        self,
        model_name: str = "gpt-5-mini",
        language: str = "Cpp",
        bug_type: str = "NPD",
        files: str = "*.c",
        max_workers: int | None = None,
    ) -> None:
        self.model_name = model_name
        self.language = language
        self.bug_type = bug_type
        self.files = files
        self.thread_safe = True  # subprocess per call; no shared engine state
        # None = unbounded (one thread per record, current behavior). Each detect
        # already runs --max-neural-workers 30 internally, so cap this if a caller
        # sends large batches to avoid an API storm (N x 30 concurrent calls).
        self._max_workers = max_workers

    def detect(self, record: dict) -> dict:
        before = record.get("context_before", record.get("context", ""))
        after  = record.get("context_after", "")
        tf     = record.get("target_function", "")
        parts  = [p for p in [before, tf, after] if p]
        code   = "\n\n".join(parts).strip()
        file_name = record.get("file_name") or "solution.c"
        case_stem = Path(file_name).stem
        auxiliary = record.get("auxiliary_file", "").strip()

        with tempfile.TemporaryDirectory(prefix="repoaudit_det_") as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True, exist_ok=True)
            (project_dir / file_name).write_text(code)
            if auxiliary:
                (project_dir / "auxiliary.cc").write_text(auxiliary)

            result_root = Path(tmp) / "ra_out"
            env = os.environ.copy()
            env["RA_RESULT_ROOT"] = str(result_root)
            env["LANGUAGE"] = self.language
            env["MODEL"] = self.model_name

            cmd = [
                "bash",
                str(REPOAUDIT_DIR / "run_repoaudit.sh"),
                str(project_dir),
                self.bug_type,
                self.files,
            ]
            subprocess.run(cmd, cwd=REPOAUDIT_DIR, env=env, check=True)

            # Find latest run dir
            model_slug = self.model_name.replace("/", "_")
            proj_name = project_dir.name
            res_base = result_root / "result" / "dfbscan" / model_slug / self.bug_type / self.language / proj_name
            run_dirs = sorted(res_base.glob("*"))
            if not run_dirs:
                return {"verdict": "safe", "reasoning": "RepoAudit produced no results.", "votes": {}}
            latest = run_dirs[-1]

            verdict = "safe"
            for summary in latest.glob("*_summary.json"):
                sdata = json.loads(summary.read_text())
                if sdata.get("flag") == "tp":
                    verdict = "vulnerable"
                    break

            detect_info = latest / "detect_info.json"
            di_text = ""
            if detect_info.exists():
                di_text = "=== REPOAUDIT_DETECT_INFO_JSON ===\n" + detect_info.read_text()

            log_dir = result_root / "log" / "dfbscan" / model_slug / self.bug_type / self.language / proj_name / latest.name
            log_parts = []
            for log_file in sorted(log_dir.glob("*.log")) if log_dir.exists() else []:
                log_parts.append(f"=== {log_file.name} ===\n" + log_file.read_text())
            logs = "\n\n".join(log_parts)

            reasoning = "\n\n".join([t for t in [logs, di_text] if t]).strip()
            return {"verdict": verdict, "reasoning": reasoning, "votes": {}}

    def detect_batch(self, records: list[dict]) -> list[dict]:
        if not records:
            return []
        workers = len(records) if self._max_workers is None \
            else min(len(records), self._max_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.detect, records))
