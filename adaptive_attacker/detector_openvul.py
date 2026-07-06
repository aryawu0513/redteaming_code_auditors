"""
detector_openvul.py — Thin vLLM wrapper around OpenVul NPD (Qwen3-4B).

Load once via OpenVulDetector(), call detect() many times.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

# vllm 0.8.x + transformers 5.x compat shim (mirrors OpenVul/run.py)
try:
    from transformers import Qwen2Tokenizer
    if not hasattr(Qwen2Tokenizer, "all_special_tokens_extended"):
        Qwen2Tokenizer.all_special_tokens_extended = property(
            lambda self: list(self.all_special_tokens)
        )
except Exception:
    pass

from OpenVul.run_local_bench import build_user_prompt, parse_verdict, SYSTEM_PROMPT  # noqa: E402


class OpenVulDetector:
    """
    Wraps OpenVul NPD Qwen3-4B via vLLM.  Load the model once; call detect() per round.

    Uses pass@1 (n=1, single sample) — majority voting was dropped.
    """

    def __init__(
        self,
        model_id: str = "Leopo1d/OpenVul-Qwen3-4B-GRPO",
        tp: int = 1,
        n: int = 1,
        temperature: float = 0.6,
        mode: str = "npd",
        defense_text: str | None = None,
    ) -> None:
        from vllm import LLM, SamplingParams  # import here to avoid slow import at module level

        self.default_mode = mode  # which CWE prompt line detect()/detect_batch() use by default
        self.defense_text = defense_text  # comment-trust policy appended to the system prompt

        print(f"[detector] Loading {model_id} (tp={tp}) …", flush=True)
        self.llm = LLM(model=model_id, tensor_parallel_size=tp)
        self.tokenizer = self.llm.get_tokenizer()
        self.params = SamplingParams(
            n=n,
            temperature=temperature,
            top_p=0.95,
            top_k=20,
            min_p=0,
            max_tokens=32768,
        )
        self.thread_safe = False  # shared vLLM LLM instance; not thread-safe

    def _build_prompt(self, record: dict, mode: str) -> str:
        # Build context: auxiliary + same-file before + same-file after
        auxiliary = record.get("auxiliary_file", "").strip()
        before    = record.get("context_before", record.get("context", ""))
        after     = record.get("context_after", "")
        ctx_parts = [p for p in [before, after, auxiliary] if p]
        if ctx_parts:
            record = {**record, "context": "\n\n".join(ctx_parts)}
        user_prompt = build_user_prompt(record, mode)
        if self.defense_text:
            user_prompt = user_prompt + "\n\n" + self.defense_text.strip()
        return self.tokenizer.apply_chat_template(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=True,
        )

    @staticmethod
    def _parse_output(output) -> dict:
        raw_outputs = [o.text for o in output.outputs]
        votes: dict[str, int] = {"has_vul": 0, "no_vul": 0}
        for text in raw_outputs:
            v = parse_verdict(text)
            if v == "has_vul":
                votes["has_vul"] += 1
            else:
                votes["no_vul"] += 1
        majority = "yes" if votes["has_vul"] >= votes["no_vul"] else "no"
        verdict = "vulnerable" if majority == "yes" else "safe"
        return {
            "verdict": verdict,
            "reasoning": raw_outputs[0] if raw_outputs else "",
            "all_outputs": raw_outputs,
            "votes": votes,
        }

    def detect(self, record: dict, mode: str | None = None) -> dict:
        """
        Run the detector on a dataset record.

        Args:
            record: OpenVul-format dict (context, target_function, function_name, file_name, …)
            mode:   'npd', 'uaf', or 'generic'. Defaults to self.default_mode
                    (set at construction) so callers that don't know about
                    bug-type framing still get the right prompt.

        Returns:
            {
              "verdict":     "safe" | "vulnerable",
              "reasoning":   str  (first output, includes <think> chain),
              "all_outputs": list[str],
              "votes":       {"has_vul": int, "no_vul": int},
            }
        """
        prompt_str = self._build_prompt(record, mode or self.default_mode)
        output = self.llm.generate([prompt_str], self.params)[0]
        return self._parse_output(output)

    def detect_batch(self, records: list[dict], mode: str | None = None) -> list[dict]:
        """
        Run the detector on several records in ONE vLLM call.

        vLLM batches the prompts natively (continuous batching), so N records
        cost far less wall-clock than N sequential detect() calls. Returns one
        result dict per input record, in order.
        """
        if not records:
            return []
        mode = mode or self.default_mode
        prompts = [self._build_prompt(r, mode) for r in records]
        outputs = self.llm.generate(prompts, self.params)
        return [self._parse_output(o) for o in outputs]
