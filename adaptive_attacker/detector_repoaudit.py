"""
detector_repoaudit.py — RepoAudit wrapper with OpenVulDetector-like interface.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
REPOAUDIT_DIR = REPO_ROOT / "RepoAudit" / "src"

# A log record is one timestamped line: "2026-06-21 23:16:44,032 - INFO - ..."
_LOG_RECORD = r"\n\d{4}-\d{2}-\d{2} \d\d:\d\d:\d\d"
# The LLM's answer is "Answer: Yes" / "Answer: No" on its own — that marks a
# PathValidator (validator) response. Explorer responses end with "Answer: <values>".
_VALIDATOR_ANSWER = re.compile(r"Answer:\s*(Yes|No)\b\.?\s*$", re.MULTILINE)
_RESPONSE_BLOCK = re.compile(
    r"Response:\s*\n(.*?)(?=" + _LOG_RECORD + r"|\Z)", re.DOTALL
)


def extract_ra_reasoning(raw_log: str) -> str:
    """Pull the LLM's own reasoning out of a (possibly parallel/interleaved) RepoAudit log.

    RepoAudit runs ~30 workers, so explorer dispatch headers and their Response
    blocks are interleaved out of order — splitting on dispatch headers (as the
    demo viewer does) loses almost everything. Instead we grab every "Response:"
    block directly (each is logged atomically as one record) and label it
    explorer vs validator by whether its answer is a bare Yes/No.
    """
    blocks = []
    for m in _RESPONSE_BLOCK.finditer(raw_log):
        body = m.group(1).strip()
        if not body:
            continue
        kind = "VALIDATOR" if _VALIDATOR_ANSWER.search(body) else "EXPLORER"
        blocks.append((kind, body))
    out = []
    for i, (kind, body) in enumerate(blocks, 1):
        out.append(f"─── {kind} #{i} ───\n{body}")
    return "\n\n".join(out)


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
        files: str = "",
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

            # Reasoning = the LLM's own analysis: the explorer (IntraDataFlowAnalyzer)
            # and validator (PathValidator) Response blocks from the per-file logs.
            # This is what the model actually reasoned about each candidate path —
            # NOT the structured detect_info.json bug report. Extracted here, before
            # the temp dir is deleted, for both safe and vulnerable verdicts.
            log_dir = result_root / "log" / "dfbscan" / model_slug / self.bug_type / self.language / proj_name / latest.name
            parts = []
            if log_dir.exists():
                for log_file in sorted(log_dir.glob("*.log")):
                    if log_file.name == "dfbscan.log":
                        continue  # only execution metadata, no LLM content
                    reasoning_text = extract_ra_reasoning(log_file.read_text())
                    if reasoning_text:
                        parts.append(reasoning_text)
            reasoning = "\n\n".join(parts)

            return {"verdict": verdict, "reasoning": reasoning, "votes": {}}

    def detect_batch(self, records: list[dict]) -> list[dict]:
        if not records:
            return []
        workers = len(records) if self._max_workers is None \
            else min(len(records), self._max_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.detect, records))
