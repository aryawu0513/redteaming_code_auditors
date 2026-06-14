"""
detector_vulnllmr.py — VulnLLM-R agent scaffold wrapper for adaptive attacker.

Uses agent_scaffold.scan (agentic mode: call-graph context + policy-based CWE
exploration) rather than the function-level vulscan.test.test evaluator.

Agentic mode chosen because it has 86% baseline TPR vs 57% function-level on
attacker_lcb, and handles complex multi-function code better via call-graph context.
Parameters match run_scaffold_attacks.py: policy_runs=4, n_paths=2, max_rounds=3.

Same output interface as OpenVulDetector: detect(record) → {"verdict", "reasoning", "votes"}.
"""

import sys
import tempfile
from pathlib import Path

VULNLLMR_ROOT = Path(__file__).parent.parent / "VulnLLM-R"
sys.path.insert(0, str(VULNLLMR_ROOT))
sys.path.insert(0, str(VULNLLMR_ROOT / "vulscan" / "model_zoo" / "src"))

from agent_scaffold.scan import scan_project, make_vllm_fns  # noqa: E402


class VulnLLMRDetector:
    """
    Wraps VulnLLM-R-7B in agentic (agent scaffold) mode. Load once; call detect() per round.

    Each detect() writes the record's code to a temp directory and runs scan_project
    with policy_runs=4 (4 exploratory CWE-hunting queries at temp=0.6, then 1
    final verdict at temp=0.0).
    """

    def __init__(
        self,
        model_id: str = "UCSB-SURFI/VulnLLM-R-7B",
        tp: int = 1,
        max_tokens: int = 4096,
        policy_runs: int = 0,
        n_paths: int = 3,
        max_rounds: int = 3,
    ) -> None:
        self._policy_runs = policy_runs
        self._n_paths = n_paths
        self._max_rounds = max_rounds
        print(f"[detector] Loading {model_id} via agent scaffold …", flush=True)
        # make_vllm_fns returns (model_fn@temp=0.0, model_fn_diverse@temp=0.6)
        self.model_fn, self.model_fn_diverse = make_vllm_fns(model_id, max_tokens=max_tokens)

    def detect(self, record: dict) -> dict:
        file_name = record.get("file_name", "solution.c")
        suffix = Path(file_name).suffix.lower()
        if suffix in (".cc", ".cpp", ".cxx"):
            language = "cpp"
        else:
            language = "c"
            if suffix not in (".c", ".h"):
                file_name = "solution.c"
        target_fn = record.get("function_name") or None

        with tempfile.TemporaryDirectory() as tmpdir:
            # Reconstruct source file so the detector always sees the current
            # target_function (which may have annotations injected during the
            # attack loop). Sandwich the function between before/after context.
            before = record.get("context_before", record.get("context", ""))
            after  = record.get("context_after", "")
            target_function = record.get("target_function", "")
            parts = [p for p in [before, target_function, after] if p]
            code = "\n\n".join(parts).strip()
            # Strip bare class-access-specifier preamble (e.g. "public:\n") that
            # appears in CVE dataset snippets extracted from class bodies.
            import re as _re
            code = _re.sub(r'^\s*(public|private|protected)\s*:\s*\n', '', code)
            (Path(tmpdir) / file_name).write_text(code)

            # Write cross-file auxiliary as a separate file so VulnLLM-R's
            # rglob traversal can see it alongside the main file.
            auxiliary = record.get("auxiliary_file", "").strip()
            if auxiliary:
                aux_name = "auxiliary.cc" if language == "cpp" else "auxiliary.c"
                (Path(tmpdir) / aux_name).write_text(auxiliary)

            results = scan_project(
                repo_dir=tmpdir,
                language=language,
                model_fn=self.model_fn,
                n_paths=self._n_paths,
                max_rounds=self._max_rounds,
                policy_runs=self._policy_runs,
                model_fn_diverse=self.model_fn_diverse,
                target_functions=[target_fn] if target_fn else None,
                cwe_hints=["CWE-476"],
                verbose=False,
            )

        if not results:
            return {
                "verdict": "error",
                "reasoning": "scan error: no functions parsed (unparseable file)",
                "all_outputs": [],
                "votes": {},
            }

        target_result = next(
            (r for r in results if r["function"] == target_fn),
            results[0] if results else {},
        )

        judge = target_result.get("judge", "no")
        raw = target_result.get("output", "")
        verdict = "vulnerable" if judge == "yes" else "safe"
        votes = {"has_vul": 1, "no_vul": 0} if judge == "yes" else {"has_vul": 0, "no_vul": 1}
        return {
            "verdict": verdict,
            "reasoning": raw,
            "all_outputs": [raw],
            "votes": votes,
        }

    def detect_batch(self, records: list[dict]) -> list[dict]:
        """
        Interface parity with OpenVulDetector.detect_batch.

        The agent scaffold runs its own multi-call exploration loop per record
        (policy_runs queries + a final verdict) and exposes no cross-record
        batching hook, so this simply loops detect(). No real wall-clock saving
        here — the batched fast path is OpenVul-only.
        """
        return [self.detect(r) for r in records]
