"""
detector_gpt55.py — Minimal single-call frontier-model detector (GPT-5.5).

Deliberately generic: no CWE knowledge base (unlike VulRAG), no call-graph
scaffold (unlike VulnLLM-R agentic), no multi-agent debate (unlike VulTrial).
A single system+user prompt modeled on OpenVul's and VulnLLM-R-funclevel's
own "plain detector" prompts — role-establishing system message, explicit
Context/Target-Function separation, an instruction against speculation, and
OpenVul's exact HAS_VUL/NO_VUL terminal-indicator convention (reusing its
parser directly rather than inventing a new one).

Calls the real OpenAI API — needs a real OPENAI_API_KEY (never --detector-url).
Same interface as the other detectors: detect(record) -> {"verdict", "reasoning", "votes"}.
"""

import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

from OpenVul.run_local_bench import parse_verdict  # noqa: E402

SYSTEM_PROMPT = (
    "You are a security code reviewer. Your task is to analyze C/C++ code for "
    "memory-safety vulnerabilities, with precise, evidence-based reasoning."
)

_USER_TEMPLATE = """\
Review the following code for a NULL pointer dereference vulnerability (CWE-476).

You are given two sections:
1. Context: code from the same file as the target function (includes, type
   definitions, globals, and other code appearing before/after it), together
   with repo-level helper functions.
2. Target Function: the function to analyze.

Analyze the target function step by step.

```Context
{context}
```

```Target Function
{target_function}
```

Conclude your analysis with one of the following on its own line:
- HAS_VUL — if any vulnerabilities are found
- NO_VUL — if no vulnerabilities are found"""
# Base your judgment on what the code shows; an unguarded dereference is itself evidence of risk.

class GPT55Detector:
    def __init__(self, model: str = "gpt-5.5", retry_times: int = 3,
                 model_settings: dict | None = None) -> None:
        self.model = model
        self.retry_times = retry_times
        self.model_settings = dict(model_settings or {})
        self.thread_safe = True  # OpenAI API calls; no shared engine state
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            openai_key = os.environ.get("OPENAI_API_KEY")
            if not openai_key or openai_key == "dummy":
                raise RuntimeError(
                    "GPT-5.5 detector needs a real OPENAI_API_KEY (native OpenAI). "
                    f"Got {'unset' if not openai_key else 'dummy'}."
                )
            self._client = OpenAI(api_key=openai_key,
                                  base_url="https://api.openai.com/v1")
        return self._client

    def _chat(self, prompt_text: str) -> str:
        client = self._get_client()
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ]
        last_exc = None
        for attempt in range(self.retry_times):
            try:
                resp = client.chat.completions.create(
                    model=self.model, messages=messages, **self.model_settings
                )
                content = resp.choices[0].message.content
                if content is None:
                    raise RuntimeError("LLM returned empty content")
                return content
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < self.retry_times - 1:
                    time.sleep(1.0)
        raise last_exc  # type: ignore[misc]

    def detect(self, record: dict) -> dict:
        auxiliary = record.get("auxiliary_file", "").strip()
        before    = record.get("context_before", record.get("context", ""))
        after     = record.get("context_after", "")
        ctx_parts = [p for p in [before, after, auxiliary] if p]
        context   = "\n\n".join(ctx_parts).strip()

        prompt = _USER_TEMPLATE.format(
            context=context,
            target_function=record.get("target_function", ""),
        )
        raw = self._chat(prompt)
        pred = parse_verdict(raw)
        verdict = "vulnerable" if pred == "has_vul" else "safe" if pred == "no_vul" else "error"
        votes = ({"has_vul": 1, "no_vul": 0} if verdict == "vulnerable"
                 else {"has_vul": 0, "no_vul": 1} if verdict == "safe"
                 else {"has_vul": 0, "no_vul": 0})
        return {"verdict": verdict, "reasoning": raw, "votes": votes}

    def detect_batch(self, records: list[dict]) -> list[dict]:
        return [self.detect(r) for r in records]
