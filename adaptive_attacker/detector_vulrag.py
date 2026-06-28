"""
detector_vulrag.py — Vul-RAG wrapper with the OpenVul/VulTrial-style detector interface.

Vul-RAG (Du et al.) is a FUNCTION-LEVEL, retrieval-augmented vulnerability detector:
given one C function it (1) summarizes the function's purpose/functionality via an LLM,
(2) BM25-retrieves matching CVE knowledge entries from a knowledge base (KB), and
(3) asks an LLM to judge "vulnerable / not vulnerable", concluding each judgement with
`<result> YES </result>` or `<result> NO </result>`.

KNOWLEDGE BASE CAVEAT
---------------------
The bundled KB is Linux-kernel CWE-476 (NULL-pointer-dereference) knowledge
(`Vul-RAG/vulnerability knowledge/linux_kernel_CWE-476_knowledge.json`). Our adversarial
benchmark spans *other* C/C++ projects, so the retrieved knowledge is only loosely
in-domain. This is a deliberate fair-use approximation of the published Vul-RAG pipeline,
not a claim that the KB covers our targets. Swap `kb_path` to use a different KB.

LLM ROUTING
-----------
All LLM calls go through native OpenAI: base_url `https://api.openai.com/v1`, key
from env `OPENAI_API_KEY`, model from env `VULRAG_MODEL` (default `gpt-4o-mini`,
faithful to the original Vul-RAG). OpenRouter is intentionally NOT used — it needs
the `openai/`-prefixed model id and rejects plain `gpt-4o-mini` as "invalid model ID".
We use the `openai` Python SDK. The detector matches the existing detector interface:
`detect(record) -> {"verdict", "reasoning", "votes"}` and `detect_batch(records)`.

The KB is indexed ONCE in __init__ (three BM25 retrievers over purpose / function /
code-before-change fields, exactly as the original `vulnerability_detect.py`), then reused
across every detect call. We vendor a small self-contained BM25Okapi + tokenizer so we do
not depend on Vul-RAG's spacy/rank_bm25 stack (which is not installed here); the ranking
formula is unchanged.
"""
from __future__ import annotations

import math
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_KB_PATH = (
    REPO_ROOT
    / "Vul-RAG"
    / "vulnerability knowledge"
    / "linux_kernel_CWE-476_knowledge.json"
)

# Per-field retrieval weights (identical to vulnerability_detect.retrieve_weight).
RETRIEVE_WEIGHT = {"purpose": 1, "function": 1, "code": 1}


# ===========================================================================
# Self-contained BM25 (faithful to rank_bm25.BM25Okapi defaults k1=1.5, b=0.75)
# ===========================================================================
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase word/identifier tokenizer (regex fallback for spaCy)."""
    if not text:
        return []
    return _TOKEN_RE.findall(text.lower())


class _BM25Retriever:
    """Minimal BM25Okapi retriever with the same .set_corpus()/.search() API
    as Vul-RAG's utils.bm25_retriever.BM25Retriever."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.corpus_size = 0
        self.avgdl = 0.0
        self.doc_freqs: list[Counter] = []
        self.idf: dict[str, float] = {}
        self.doc_len: list[int] = []

    def set_corpus(self, corpus: list[str]) -> None:
        tokenized = [_tokenize(doc) for doc in corpus]
        self.corpus_size = len(tokenized)
        self.doc_len = [len(d) for d in tokenized]
        self.avgdl = (sum(self.doc_len) / self.corpus_size) if self.corpus_size else 0.0

        df: Counter = Counter()
        self.doc_freqs = []
        for doc in tokenized:
            freqs = Counter(doc)
            self.doc_freqs.append(freqs)
            for term in freqs:
                df[term] += 1

        # BM25Okapi idf (matches rank_bm25, including its epsilon floor).
        idf_sum = 0.0
        negative = []
        self.idf = {}
        for term, freq in df.items():
            idf = math.log(self.corpus_size - freq + 0.5) - math.log(freq + 0.5)
            self.idf[term] = idf
            idf_sum += idf
            if idf < 0:
                negative.append(term)
        avg_idf = (idf_sum / len(self.idf)) if self.idf else 0.0
        eps = 0.25 * avg_idf
        for term in negative:
            self.idf[term] = eps

    def _scores(self, query: str) -> list[float]:
        q_tokens = _tokenize(query)
        scores = [0.0] * self.corpus_size
        for term in q_tokens:
            if term not in self.idf:
                continue
            idf = self.idf[term]
            for i in range(self.corpus_size):
                f = self.doc_freqs[i].get(term, 0)
                if f == 0:
                    continue
                denom = f + self.k1 * (
                    1 - self.b + self.b * self.doc_len[i] / (self.avgdl or 1)
                )
                scores[i] += idf * (f * (self.k1 + 1) / denom)
        return scores

    def search(self, query: str, top_n: int = -1) -> list[int]:
        if self.corpus_size == 0:
            return []
        scores = self._scores(query)
        order = sorted(range(self.corpus_size), key=lambda i: scores[i], reverse=True)
        return order if top_n == -1 else order[:top_n]


# ===========================================================================
# Prompt builders (verbatim from src/vulnerability_detect.py)
# ===========================================================================
def _extraction_prompts(code_snippet: str) -> tuple[str, str]:
    prefix_str = f"""This is a code snippet: \n{code_snippet}\n"""
    purpose_prompt = prefix_str + (
        "What is the purpose of the function in the above code snippet? "
        "Please summarize the answer in one sentence with the following format: "
        'Function purpose: ""'
    )
    function_prompt = prefix_str + (
        "Please summarize the functions of the above code snippet "
        "in the list format without other explanation: "
        '"The functions of the code snippet are: 1. 2. 3."'
    )
    return purpose_prompt, function_prompt


def _detect_vul_prompt(code_snippet: str, cve_knowledge) -> str:
    return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a similar vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please check if the above code snippet contains similar vulnerability behaviors mentioned in the vulnerability knowledge. Perform a step-by-step analysis and conclude your response with either <result> YES </result> or <result> NO </result>.
"""


def _detect_sol_prompt(code_snippet: str, cve_knowledge) -> str:
    return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there are similar necessary solution behaviors in the code snippet, which can prevent the occurrence of related vulnerabilities in the vulnerability knowledge.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please check if the above code snippet contains similar solution behaviors mentioned in the vulnerability knowledge. Perform a step-by-step analysis and conclude your response with either <result> YES </result> or <result> NO </result>.
"""


# ===========================================================================
# Output parsing helpers (verbatim semantics from vulnerability_detect.py)
# ===========================================================================
def _remove_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)


def _extract_result_from_output(output: str) -> int:
    """1 if <result> YES </result>, 0 if NO. Raises ValueError on malformed output."""
    matches = re.findall(r"<result>(.*?)</result>", output, re.IGNORECASE | re.DOTALL)
    if not matches:
        raise ValueError("No <result> and </result> tags found")
    result_content = matches[-1].strip().upper()
    if "YES" in result_content:
        return 1
    if "NO" in result_content:
        return 0
    raise ValueError(f"Result contains neither YES nor NO: {result_content!r}")


def _extract_by_prefix(response: str, prefix: str) -> str:
    if prefix in response:
        return response.split(prefix)[1].strip()
    return response.strip()


# ===========================================================================
# Detector
# ===========================================================================
class VulRAGDetector:
    """Function-level Vul-RAG detector routed through OpenRouter.

    Load/index the KB once in __init__, then call detect()/detect_batch() repeatedly.
    """

    def __init__(
        self,
        model: str | None = None,
        kb_path: str | os.PathLike = DEFAULT_KB_PATH,
        retrieval_top_k: int = 10,
        max_knowledge: int = 5,
        summary_model: str | None = None,
        retry_times: int = 3,
        model_settings: dict | None = None,
        max_workers: int | None = None,
    ) -> None:
        import json

        # Native OpenAI only (faithful to the original gpt-4o-mini Vul-RAG).
        # We deliberately do NOT fall back to OpenRouter: it requires the
        # `openai/`-prefixed model id and silently mis-routes plain `gpt-4o-mini`
        # as an "invalid model ID".
        if model:
            self.model = model
        elif os.environ.get("VULRAG_MODEL"):
            self.model = os.environ["VULRAG_MODEL"]
        else:
            self.model = "gpt-4o-mini"
        # Summary (purpose/function extraction) model defaults to the same model.
        self.summary_model = summary_model or self.model
        self.retrieval_top_k = retrieval_top_k
        self.max_knowledge = max_knowledge
        self.retry_times = retry_times
        self.model_settings = dict(model_settings or {})
        self._max_workers = max_workers
        self.thread_safe = True  # OpenAI/OpenRouter API calls; no shared mutable engine state

        self.kb_path = Path(kb_path)
        if not self.kb_path.exists():
            raise FileNotFoundError(f"Vul-RAG KB not found: {self.kb_path}")

        # --- Load + index KB ONCE ------------------------------------------
        with open(self.kb_path, "r") as f:
            knowledge_data = json.load(f)
        self.knowledge_data = knowledge_data

        # CVE_id -> list of knowledge items (one CVE may have several entries).
        self.cve_knowledge_dict: dict[str, list] = {}
        for item in knowledge_data:
            self.cve_knowledge_dict.setdefault(item["CVE_id"], []).append(item)

        purpose_list = [item.get("purpose", "") or "" for item in knowledge_data]
        function_list = [item.get("function", "") or "" for item in knowledge_data]
        code_list = [item.get("code_before_change", "") or "" for item in knowledge_data]

        self.purpose_retriever = _BM25Retriever()
        self.purpose_retriever.set_corpus(purpose_list)
        self.function_retriever = _BM25Retriever()
        self.function_retriever.set_corpus(function_list)
        self.code_retriever = _BM25Retriever()
        self.code_retriever.set_corpus(code_list)

        # Lazily-created OpenAI/OpenRouter client (so __init__ needs no API key).
        self._client = None

    # ------------------------------------------------------------------ LLM
    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            # Native OpenAI only — never OpenRouter (see __init__ note). Require a
            # real key; the dummy key used for the Qwen refiner won't authenticate.
            openai_key = os.environ.get("OPENAI_API_KEY")
            if not openai_key or openai_key == "dummy":
                raise RuntimeError(
                    "Vul-RAG needs a real OPENAI_API_KEY (native OpenAI). "
                    f"Got {'unset' if not openai_key else 'dummy'}."
                )
            self._client = OpenAI(api_key=openai_key,
                                  base_url="https://api.openai.com/v1")
        return self._client

    def _chat(self, model: str, prompt_text: str) -> str:
        """Single-message chat completion with simple retry/backoff."""
        client = self._get_client()
        messages = [{"role": "user", "content": prompt_text}]
        last_exc = None
        for attempt in range(self.retry_times):
            try:
                resp = client.chat.completions.create(
                    model=model, messages=messages, **self.model_settings
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

    # ------------------------------------------------------------- retrieval
    def _retrieve_knowledge(self, code_snippet: str, purpose: str, function: str) -> list[dict]:
        """Faithful port of retrieve_knowledge_by_cve() from vulnerability_detect.py."""
        knowledge_data = self.knowledge_data
        top_k = self.retrieval_top_k

        purpose_index = self.purpose_retriever.search(purpose, top_n=top_k)
        function_index = self.function_retriever.search(function, top_n=top_k)
        code_index = self.code_retriever.search(code_snippet, top_n=top_k)

        def _cve_order(indices: list[int]) -> list[str]:
            seen: list[str] = []
            for idx in indices:
                cve = knowledge_data[idx]["CVE_id"]
                if cve not in seen:
                    seen.append(cve)
            return seen

        purpose_cve_list = _cve_order(purpose_index)
        function_cve_list = _cve_order(function_index)
        code_cve_list = _cve_order(code_index)

        cve_retrieved_list = list(set(purpose_cve_list + function_cve_list + code_cve_list))

        # Rank retrieved CVEs (lower combined rank = better), as in the original.
        cve_id_dict: dict[str, int] = {}
        for cve_id in cve_retrieved_list:
            p = purpose_cve_list.index(cve_id) if cve_id in purpose_cve_list else len(purpose_cve_list)
            fn = function_cve_list.index(cve_id) if cve_id in function_cve_list else len(function_cve_list)
            c = code_cve_list.index(cve_id) if cve_id in code_cve_list else len(code_cve_list)
            cve_id_dict[cve_id] = (
                p * RETRIEVE_WEIGHT["purpose"]
                + fn * RETRIEVE_WEIGHT["function"]
                + c * RETRIEVE_WEIGHT["code"]
            )
        sorted_cve_list = [cid for cid, _ in sorted(cve_id_dict.items(), key=lambda x: x[1])]

        final_knowledge_list: list[dict] = []
        for cve_id in sorted_cve_list[: self.max_knowledge]:
            items = self.cve_knowledge_dict[cve_id]
            item_purpose_list = [it.get("purpose", "") or "" for it in items]
            item_function_list = [it.get("function", "") or "" for it in items]
            item_code_list = [it.get("code_before_change", "") or "" for it in items]

            ipr = _BM25Retriever(); ipr.set_corpus(item_purpose_list)
            item_purpose_index = ipr.search(purpose, top_n=-1)
            ifr = _BM25Retriever(); ifr.set_corpus(item_function_list)
            item_function_index = ifr.search(function, top_n=-1)
            icr = _BM25Retriever(); icr.set_corpus(item_code_list)
            item_code_index = icr.search(code_snippet, top_n=-1)

            item_score_dict: dict[int, int] = {}
            for idx in range(len(items)):
                pp = item_purpose_index.index(idx) if idx in item_purpose_index else len(item_purpose_index)
                fp = item_function_index.index(idx) if idx in item_function_index else len(item_function_index)
                cp = item_code_index.index(idx) if idx in item_code_index else len(item_code_index)
                item_score_dict[idx] = (
                    pp * RETRIEVE_WEIGHT["purpose"]
                    + fp * RETRIEVE_WEIGHT["function"]
                    + cp * RETRIEVE_WEIGHT["code"]
                )
            sorted_items = sorted(item_score_dict.items(), key=lambda x: x[1])
            if sorted_items:
                final_knowledge_list.append(items[sorted_items[0][0]])

        ans = final_knowledge_list[: min(self.max_knowledge, len(final_knowledge_list))]

        return_knowledge_list: list[dict] = []
        for knowledge in ans:
            return_knowledge_list.append({
                "cve_id": knowledge["CVE_id"],
                "vulnerability_behavior": {
                    "vulnerability_cause_description": knowledge.get("vulnerability_cause_description"),
                    "trigger_condition": knowledge.get("trigger_condition"),
                    "specific_code_behavior_causing_vulnerability": knowledge.get(
                        "specific_code_behavior_causing_vulnerability"
                    ),
                },
                "solution_behavior": knowledge.get("solution"),
            })
        return return_knowledge_list

    # ----------------------------------------------------------------- detect
    def _detect_code(self, code: str) -> dict:
        """Port of detect_code() from vulnerability_detect.py (vul+sol judgement loop)."""
        purpose_prompt, function_prompt = _extraction_prompts(code)

        purpose_output = self._chat(self.summary_model, purpose_prompt)
        purpose = _extract_by_prefix(purpose_output, "Function purpose:")

        function_output = self._chat(self.summary_model, function_prompt)
        function = _extract_by_prefix(function_output, "The functions of the code snippet are:")

        knowledge_list = self._retrieve_knowledge(code, purpose, function)

        detect_result = []
        final_result = -1  # -1 = no knowledge flagged it (treated as safe)
        for vul_knowledge in knowledge_list:
            vul_prompt = _detect_vul_prompt(code, vul_knowledge)
            sol_prompt = _detect_sol_prompt(code, vul_knowledge)

            vul_output = self._chat(self.model, vul_prompt)
            sol_output = self._chat(self.model, sol_prompt)

            detect_result.append({
                "cve_id": vul_knowledge.get("cve_id"),
                "vul_output": vul_output,
                "sol_output": sol_output,
            })

            vul_result = _extract_result_from_output(_remove_thinking(vul_output))
            sol_result = _extract_result_from_output(_remove_thinking(sol_output))

            # Vulnerable iff vul-behavior present AND solution-behavior absent.
            if vul_result == 1 and sol_result == 0:
                final_result = 1
                break

        return {
            "purpose": purpose,
            "function": function,
            "detect_result": detect_result,
            "final_result": final_result,
        }

    def detect(self, record: dict) -> dict:
        """Run Vul-RAG on record['target_function'] (a single C function).

        Returns {"verdict": "vulnerable"|"safe"|"error", "reasoning": str, "votes": {}}.
        verdict == "vulnerable" iff a retrieved knowledge entry concludes
        <result> YES </result> (vuln present) with <result> NO </result> (solution absent).
        """
        code = record.get("target_function", "") or ""
        if not code.strip():
            return {"verdict": "error", "reasoning": "empty target_function", "votes": {}}
        try:
            out = self._detect_code(code)
        except Exception as exc:  # noqa: BLE001
            return {"verdict": "error", "reasoning": f"Vul-RAG error: {exc}", "votes": {}}

        verdict = "vulnerable" if out["final_result"] == 1 else "safe"
        # Reasoning: the flagging judgement if vulnerable, else the last judgement seen.
        reasoning_parts = []
        reasoning_parts.append(f"Function purpose: {out['purpose']}")
        reasoning_parts.append(f"Functions: {out['function']}")
        for r in out["detect_result"]:
            reasoning_parts.append(
                f"\n--- knowledge {r.get('cve_id')} ---\n"
                f"[vul]\n{r.get('vul_output')}\n[sol]\n{r.get('sol_output')}"
            )
        reasoning = "\n".join(p for p in reasoning_parts if p)
        votes = {"checked": len(out["detect_result"]), "final_result": out["final_result"]}
        return {"verdict": verdict, "reasoning": reasoning, "votes": votes}

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
