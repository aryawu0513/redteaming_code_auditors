"""
screening_cache.py — disk cache in front of screening_agent.screen_payload().

Keyed by sha256(code), so all D4 representations of the same payload reuse one
screening call. The labeled representation is derived from D4's audit, not a
separate LLM call.
"""
import hashlib
import json
from pathlib import Path

DEFAULT_CACHE_DIR = Path(__file__).parent / "screening_cache"
CACHE_SCHEMA_VERSION = "d4-v2"


def get_or_screen(code: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> dict:
    from defenses.screening_agent import screen_payload

    cache_dir.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(f"{CACHE_SCHEMA_VERSION}:{code}".encode()).hexdigest()[:16]
    cache_file = cache_dir / f"{key}.json"
    if cache_file.exists():
        return json.loads(cache_file.read_text())

    result = screen_payload(code)
    cache_file.write_text(json.dumps(result, indent=2))
    return result
