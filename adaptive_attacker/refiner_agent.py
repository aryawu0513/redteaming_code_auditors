"""
refiner_agent.py — LLM refiner via OpenAI-compatible API.

Pure text-in / text-out transform. No tool access.
Standard sampling params (temperature, top_p, presence_penalty) are passed
as first-class kwargs. vLLM-only params (top_k, min_p, repetition_penalty)
are forwarded via extra_body — the real OpenAI API ignores unknown body fields,
vLLM honours them.
"""

import json
import os
from functools import lru_cache
from pathlib import Path

import yaml
from openai import OpenAI

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        base_url = (
            os.environ.get("OPENAI_BASE_URL")
            or os.environ.get("OPENAI_API_BASE")
            or None
        )
        _client = OpenAI(base_url=base_url)
    return _client


@lru_cache(maxsize=1)
def _load_bootstrap_config() -> dict:
    cfg_path = Path(__file__).parent / "config_bootstrapper.yaml"
    with open(cfg_path) as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def _load_refiner_fromscratch_config() -> dict:
    cfg_path = Path(__file__).parent / "config_refiner_fromscratch.yaml"
    with open(cfg_path) as f:
        return yaml.safe_load(f)


def _repair_comment(text: str) -> str:
    """Auto-close a truncated block comment (e.g. /* ... without closing */)."""
    c = text.strip()
    if c.startswith("/*") and not c.endswith("*/"):
        return c + " */"
    return c


def _annotation_is_safe_comment(text: str) -> bool:
    c = text.strip()
    if c.startswith("//"):
        return all(l.strip() == "" or l.strip().startswith("//") for l in c.split("\n"))
    if c.startswith("/*"):
        return c.endswith("*/")
    return False


def _parse_placement_result(raw: str, cfg_name: str) -> dict:
    """Shared parser for bootstrap_refine / refine_fromscratch — both return
    annotation_text + insert_before."""
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"{cfg_name} returned non-JSON: {raw[:200]}") from e
    for field in ("annotation_text", "insert_before"):
        if field not in result:
            raise ValueError(f"{cfg_name} response missing {field!r}: {raw[:200]}")
    text = _repair_comment(result["annotation_text"].strip())
    if not _annotation_is_safe_comment(text):
        raise ValueError(
            f"annotation_text is not a valid C comment (must start with /* or //): {text[:120]}"
        )
    result["annotation_text"] = text
    result["insert_before"] = result["insert_before"].strip()
    result.setdefault("rationale", "")
    return result


def bootstrap_refine(
    bundle: dict,
    model: str | None = None,
    temperature: float | None = None,
) -> dict:
    """
    Craft the first annotation from scratch using the detector's baseline reasoning.

    Uses config_bootstrapper.yaml. Returns annotation_text, insert_before,
    rationale, prompt_messages.

    Args:
        bundle: dict with keys annotation_type, target_function,
                detector_reasoning_filtered, style_spec.
        model: override model.
        temperature: override temperature.
    """
    cfg = _load_bootstrap_config()
    model = model or cfg["model"]
    temperature = temperature if temperature is not None else cfg["temperature"]

    user_content = json.dumps(bundle, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content": cfg["system_prompt"]},
        {"role": "user", "content": user_content},
    ]

    resp = _get_client().chat.completions.create(
        model=model,
        temperature=temperature,
        top_p=cfg.get("top_p", 1.0),
        presence_penalty=cfg.get("presence_penalty", 0.0),
        max_tokens=cfg.get("max_tokens", 8192),
        messages=messages,
        response_format={"type": "json_object"},
        extra_body={
            "top_k": cfg.get("top_k", -1),
            "min_p": cfg.get("min_p", 0.0),
            "repetition_penalty": cfg.get("repetition_penalty", 1.0),
        },
    )

    raw = resp.choices[0].message.content or ""
    result = _parse_placement_result(raw, "bootstrap_refine")
    result["prompt_messages"] = messages
    return result


def refine_fromscratch(
    bundle: dict,
    model: str | None = None,
    temperature: float | None = None,
) -> dict:
    """
    Refine annotation for rounds 1+ in the from-scratch loop.

    Uses config_refiner_fromscratch.yaml — permits free placement drift each
    round. Returns annotation_text, insert_before, rationale, prompt_messages.

    Args:
        bundle: dict with keys annotation_type, target_function (bare),
                detector_verdict, detector_reasoning_filtered, prior_attempts,
                style_spec, library.
    """
    cfg = _load_refiner_fromscratch_config()
    model = model or cfg["model"]
    temperature = temperature if temperature is not None else cfg["temperature"]

    user_content = json.dumps(bundle, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content": cfg["system_prompt"]},
        {"role": "user", "content": user_content},
    ]

    resp = _get_client().chat.completions.create(
        model=model,
        temperature=temperature,
        top_p=cfg.get("top_p", 1.0),
        presence_penalty=cfg.get("presence_penalty", 0.0),
        max_tokens=cfg.get("max_tokens", 8192),
        messages=messages,
        response_format={"type": "json_object"},
        extra_body={
            "top_k": cfg.get("top_k", -1),
            "min_p": cfg.get("min_p", 0.0),
            "repetition_penalty": cfg.get("repetition_penalty", 1.0),
        },
    )

    raw = resp.choices[0].message.content or ""
    result = _parse_placement_result(raw, "refine_fromscratch")
    result["prompt_messages"] = messages
    return result
