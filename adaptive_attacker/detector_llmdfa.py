"""
detector_llmdfa.py — LLMDFA wrapper with OpenVulDetector-like interface.

LLMDFA is an LLM-powered, compilation-free, tree-sitter-based data-flow
analyzer. This wrapper adapts it to FILE-level C/C++ Null-Pointer-Dereference
(NPD, CWE-476) detection:

  1. Reconstruct a single .c file from the record (context_before +
     target_function + context_after [+ auxiliary_file]), mirroring
     detector_repoaudit.py.
  2. Drive LLMDFA's DFA engine directly on that one file with bug_type="npd"
     (NPD source/sink specs + the reused dependency-flow propagator/validator).
  3. verdict == "vulnerable" iff LLMDFA reports >= 1 NPD bug.

LLM routing goes through OpenRouter (see LLMDFA/src/utility/llm.py): set
OPENROUTER_API_KEY and (optionally) LLMDFA_MODEL (default "openai/gpt-4o-mini").
"""
from __future__ import annotations

import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
LLMDFA_SRC = REPO_ROOT / "LLMDFA" / "src"

# LLMDFA's modules use top-level imports rooted at src/ (e.g. `from engine.DFA
# import DFA`, `from TSAgent...`). Make src/ importable.
if str(LLMDFA_SRC) not in sys.path:
    sys.path.insert(0, str(LLMDFA_SRC))


class LLMDFADetector:
    """
    Runs LLMDFA NPD analysis on a temp single-file C project.

    Verdict: vulnerable if LLMDFA's bug report contains >= 1 NPD finding.
    Reasoning: the LLMDFA report (sources/sinks + reported bug traces).
    """

    # Spec/flow files relative to LLMDFA/src/prompt (see run_llmdfa.py mapping).
    SRC_SPEC = "spec/npd_source.json"
    SINK_SPEC = "spec/npd_sink.json"
    PROPAGATOR_SPEC = "flow/dep_flow_propagator.json"
    VALIDATOR_SPEC = "flow/dep_flow_validator.json"
    BUG_TYPE = "NPD"

    def __init__(
        self,
        model: str | None = None,
        max_workers: int | None = None,
    ) -> None:
        # Prefer native OpenAI (`gpt-4o-mini`); the `openai/` prefix form is only
        # for OpenRouter. Pick the form by which key is present (OpenAI first),
        # matching utility/llm.py's env-based routing.
        if model:
            self.model = model
        elif os.environ.get("LLMDFA_MODEL"):
            self.model = os.environ["LLMDFA_MODEL"]
        elif os.environ.get("OPENAI_API_KEY"):
            self.model = "gpt-4o-mini"
        elif os.environ.get("OPENROUTER_API_KEY"):
            self.model = "openai/gpt-4o-mini"
        else:
            self.model = "gpt-4o-mini"
        self.thread_safe = True  # API calls; a fresh DFA engine per detect()
        # None = unbounded (one thread per record). Cap to limit concurrent
        # OpenRouter calls if a caller sends large batches.
        self._max_workers = max_workers

    def _build_code(self, record: dict) -> tuple[str, str]:
        before = record.get("context_before", record.get("context", ""))
        after = record.get("context_after", "")
        tf = record.get("target_function", "")
        parts = [p for p in [before, tf, after] if p]
        code = "\n\n".join(parts).strip()
        auxiliary = record.get("auxiliary_file", "").strip()
        if auxiliary:
            code = code + "\n\n" + auxiliary
        file_name = record.get("file_name") or "solution.c"
        # LLMDFA dispatches language by extension; force a C extension so the
        # C grammar + C node-type extractors are used.
        stem = Path(file_name).stem or "solution"
        return code, f"{stem}.c"

    def detect(self, record: dict) -> dict:
        # Imports deferred so importing the module never fails if LLMDFA deps
        # are missing until a detect is actually requested.
        from engine.DFA import DFA

        code, file_name = self._build_code(record)

        with tempfile.TemporaryDirectory(prefix="llmdfa_det_") as tmp:
            c_path = Path(tmp) / file_name
            c_path.write_text(code)
            log_dir = Path(tmp) / "log"
            log_dir.mkdir(parents=True, exist_ok=True)

            # utility/llm.py decides routing from env (OPENAI_API_KEY first,
            # then OPENROUTER_API_KEY). This passed key is only a last-resort
            # fallback when neither env var is set.
            openai_key = (
                os.environ.get("OPENAI_API_KEY")
                or os.environ.get("OPENROUTER_API_KEY")
                or "EMPTY"
            )

            try:
                engine = DFA(
                    str(c_path),
                    [],                       # support_files
                    str(log_dir),             # base_log_dir_path
                    self.BUG_TYPE,            # bug_type
                    self.SRC_SPEC,
                    self.SINK_SPEC,
                    self.PROPAGATOR_SPEC,
                    self.VALIDATOR_SPEC,
                    self.model,               # online_model_name
                    True,                     # is_syn_parser (use tree-sitter extractors)
                    False,                    # is_fscot
                    False,                    # is_syn_solver (use LLM path check)
                    1,                        # solving_refine_number
                    openai_key,
                    0.0,                      # temp
                )
                engine.analyze()
                engine.validate()
                engine.report()
            except Exception as exc:  # noqa: BLE001
                return {
                    "verdict": "error",
                    "reasoning": f"LLMDFA scan error: {exc}",
                    "votes": {},
                }

            bug_reports = getattr(engine, "bug_reports", {}) or {}
            num_bugs = sum(len(v) for v in bug_reports.values())
            verdict = "vulnerable" if num_bugs >= 1 else "safe"

            reasoning = self._format_reasoning(engine, num_bugs)
            return {"verdict": verdict, "reasoning": reasoning, "votes": {}}

    @staticmethod
    def _format_reasoning(engine, num_bugs: int) -> str:
        lines = [f"LLMDFA NPD analysis: {num_bugs} bug(s) reported."]
        env = getattr(engine, "environment", None)
        bug_reports = getattr(engine, "bug_reports", {}) or {}
        for src_fid, traces in bug_reports.items():
            for trace in traces:
                try:
                    (fid_s, v_s) = trace[0]
                    (fid_e, v_e) = trace[-1]
                    name_s = env.analyzed_functions[fid_s].function_name
                    name_e = env.analyzed_functions[fid_e].function_name
                    lines.append(
                        f"  NULL source `{v_s.name}` (line {v_s.line_number}, "
                        f"fn {name_s}) -> deref `{v_e.name}` "
                        f"(line {v_e.line_number}, fn {name_e})"
                    )
                except Exception:  # noqa: BLE001
                    lines.append(f"  bug trace: {trace}")
        return "\n".join(lines)

    def detect_batch(self, records: list[dict]) -> list[dict]:
        if not records:
            return []
        workers = (
            len(records)
            if self._max_workers is None
            else min(len(records), self._max_workers)
        )
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.detect, records))
