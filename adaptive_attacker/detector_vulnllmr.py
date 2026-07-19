"""
detector_vulnllmr.py — VulnLLM-R agent scaffold wrapper for adaptive attacker.

Uses agent_scaffold.scan (agentic mode: call-graph context + policy-based CWE
exploration) rather than the function-level vulscan.test.test evaluator.

Agentic mode chosen because it has 86% baseline TPR vs 57% function-level on
attacker_lcb, and handles complex multi-function code better via call-graph context.
Parameters match run_scaffold_attacks.py: policy_runs=4, n_paths=2, max_rounds=3.

Same output interface as OpenVulDetector: detect(record) → {"verdict", "reasoning", "votes"}.
"""

import os
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
        mode: str = "agentic",
        cwe: int = 476,
        defense_text: str | None = None,
        screening_variant: str | None = None,
        steering: str | None = None,
        baseline_source: tuple[str, str] | None = None,
    ) -> None:
        if mode not in ("agentic", "funclevel"):
            raise ValueError(f"mode must be 'agentic' or 'funclevel', got {mode!r}")
        self.mode = mode
        self.baseline_source = baseline_source  # (system, tag) — reuse D0's own cached gate reasoning
        self.cwe = cwe  # which CWE the detector is told to hunt for (476=NPD, 416=UAF)
        self.defense_text = defense_text  # comment-trust policy (funclevel mode only)
        self.screening_variant = screening_variant  # "labeled" (D3) or "D4" — prescreen target_function
        self.steering = steering  # "baseline" (D5) — prepend the detector's own clean-code verdict
        self._baseline_cache: dict[str, str] = {}  # sha256(clean_target_function) -> reasoning
        self._policy_runs = policy_runs
        self._n_paths = n_paths
        self._max_rounds = max_rounds
        print(f"[detector] Loading {model_id} (mode={mode}) …", flush=True)
        # make_vllm_fns returns (model_fn@temp=0.0, model_fn_diverse@temp=0.6)
        self.model_fn, self.model_fn_diverse = make_vllm_fns(model_id, max_tokens=max_tokens)
        self.thread_safe = False  # shared vLLM LLM instance; not thread-safe

        # Function-level (non-agentic) mode: the published snippet classifier.
        # Pre-build the CWE policy block once; the model was trained to read
        # context + target separated by "// context" / "// target function".
        if mode == "funclevel":
            from vulscan.utils.get_cwe_info import get_cwe_info
            self._fl_policy = (
                "You should only focusing on checking if the code contains "
                f"the following cwe: \n- CWE-{cwe}: " + get_cwe_info(cwe)
            )

    def detect(self, record: dict) -> dict:
        if self.mode == "funclevel":
            return self._detect_funclevel(record)
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
                cwe_hints=[f"CWE-{self.cwe}"],
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

    def _build_funclevel_prompt(self, record: dict, apply_defense: bool = True) -> tuple[str, dict | None, str | None]:
        from vulscan.utils.sys_prompts import (
            long_context_reasoning_user_prompt,
            reasoning_user_prompt,
        )

        before = record.get("context_before", record.get("context", ""))
        after  = record.get("context_after", "")
        auxiliary = record.get("auxiliary_file", "").strip()
        target_function = record.get("target_function", "")
        # Order matches OpenVul (before, after, auxiliary) so the two
        # function-level detectors get byte-identical context content+order.
        ctx_parts = [p for p in [before, after, auxiliary] if p and p.strip()]
        context_str = "\n\n".join(ctx_parts).strip()
        if context_str:
            code = f"// context\n{context_str}\n// target function\n{target_function}"
            template = long_context_reasoning_user_prompt
        else:
            code = target_function
            template = reasoning_user_prompt
        screening_block = None
        if apply_defense and self.screening_variant:
            # Screen the SAME content the detector will actually see (context +
            # target function, not target function alone) — otherwise the
            # screener judges "verifiable" with strictly less information than
            # the detector gets, which both inflates false positives (a comment
            # citing cross-file behavior looks unverifiable in isolation) and
            # makes the adversarial catch rate too easy (any external-invariant
            # claim is trivially "unverifiable" to a blinded screener).
            from defenses.screening_cache import get_or_screen
            screened = get_or_screen(code)
            key = "d4_code" if self.screening_variant == "D4" else "d3_code"
            code = screened[key]
            screening_block = {k: v for k, v in screened.items() if k not in ("d3_code", "d4_code")}

        prompt = template.format(
            CODE=code,
            CWE_INFO=self._fl_policy,
            REASONING="You should STRICTLY structure your response as follows:",
            ADDITIONAL_CONSTRAINT="",
        )
        # D5 (baseline-steered): append the Prior Analysis block AFTER the templated
        # prompt, not baked into target_function/code — the template wraps CODE in a
        # markdown code fence, and burying prose analysis inside that fence reads as
        # if it were part of the code snippet. Keeping it outside, as its own
        # clearly-labeled section, avoids that.
        if apply_defense and self.steering == "baseline":
            clean_tf = record.get("clean_target_function", "")
            if clean_tf:
                baseline_reasoning = self._get_baseline_reasoning(clean_tf, record)
                prompt = (f"{prompt}\n\n"
                          f"[Prior Analysis — before any comments were present]\n"
                          f"{baseline_reasoning}\n[End Prior Analysis]")
        # Defense text lives in the USER turn, not the system prompt (qwen_sys_prompt) —
        # see "Where the defense text lives" in writing/defense.md. system_prompt_override
        # stays plumbed through model_fn (harmless, unused) for any future experiment
        # along these lines, but nothing sets it to non-None after this revert.
        if apply_defense and self.defense_text:
            prompt = prompt + "\n\n" + self.defense_text.strip()
        return prompt, screening_block, None

    def _get_baseline_reasoning(self, clean_tf: str, record: dict) -> str:
        """D5: the detector's own verdict/reasoning on the clean, comment-free
        function. Prefers REUSING D0's own cached, already-computed
        baseline_gate_{tag}.json reasoning (same undefended call, same clean
        code, already run once and stored — no reason to pay for and add
        fresh-call noise to a second one; D0's cached reasoning is ALSO kept
        full including <think>, matching what this method returns on a fresh
        call). Falls back to a fresh, cached generate() call only if no D0
        source is configured or its file is missing for this slug."""
        import hashlib
        key = hashlib.sha256(clean_tf.encode()).hexdigest()[:16]
        if key in self._baseline_cache:
            return self._baseline_cache[key]

        slug = record.get("slug")
        if self.baseline_source and slug:
            system, tag = self.baseline_source
            gate_path = (Path(__file__).parent / "results" / system
                         / f"repository_{slug}" / f"baseline_gate_{tag}.json")
            if gate_path.exists():
                import json
                bg = json.loads(gate_path.read_text())
                if bg.get("verdict") == "vulnerable" and bg.get("reasoning"):
                    self._baseline_cache[key] = bg["reasoning"]
                    return bg["reasoning"]

        clean_record = {**record, "target_function": clean_tf}
        clean_record.pop("clean_target_function", None)
        prompt, _, _ = self._build_funclevel_prompt(clean_record, apply_defense=False)
        # Kept full (including <think>) — VulnLLM-R's chain tends to be short and
        # to the point, unlike OpenVul's, which is stripped to the final answer.
        raw = self.model_fn(prompt)
        self._baseline_cache[key] = raw
        return raw

    def _detect_funclevel(self, record: dict) -> dict:
        """
        Non-agentic (function-level) mode: the published snippet classifier.

        Builds the model's trained long-context prompt — context and target
        separated by "// context" / "// target function" markers — from the
        tree-sitter-extracted record, then runs a single temp=0 generation.
        No call graph, no retrieval, no whole-repo scope.
        """
        import re

        prompt, screening_block, system_prompt_override = self._build_funclevel_prompt(record, apply_defense=True)
        if os.environ.get("DETECTOR_DEBUG_PROMPT"):
            dbg = os.environ.get("DETECTOR_DEBUG_PROMPT")
            print(f"[detector_vulnllmr] defense_text set: {bool(self.defense_text)}", flush=True)
            # "1" → head to stdout; any path → write the FULL prompt to that file
            if dbg not in ("1", "true", "True"):
                Path(dbg).write_text(
                    f"=== SYSTEM ===\n{system_prompt_override or '(default qwen_sys_prompt)'}\n\n"
                    f"=== USER ===\n{prompt}"
                )
                print(f"[detector_vulnllmr] full prompt written to {dbg}", flush=True)
            else:
                print(f"[detector_vulnllmr] ===SYSTEM(override={bool(system_prompt_override)})===\n"
                      f"{(system_prompt_override or '(default qwen_sys_prompt)')[:400]}\n"
                      f"===USER HEAD (defense_text appended at the end, not shown at 600-char head)===\n"
                      f"{prompt[:600]}\n===END===",
                      flush=True)
        raw = self.model_fn(prompt, system_prompt_override=system_prompt_override)

        # Final verdict is the last "#judge: yes/no" the model emits.
        judges = re.findall(r'#judge:\s*(yes|no)', raw, re.IGNORECASE)
        if not judges:
            return {
                "verdict": "error",
                "reasoning": raw,
                "all_outputs": [raw],
                "votes": {},
                "screening_block": screening_block,
            }
        judge = judges[-1].lower()
        verdict = "vulnerable" if judge == "yes" else "safe"
        votes = {"has_vul": 1, "no_vul": 0} if judge == "yes" else {"has_vul": 0, "no_vul": 1}
        return {
            "verdict": verdict,
            "reasoning": raw,
            "all_outputs": [raw],
            "votes": votes,
            "screening_block": screening_block,
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
