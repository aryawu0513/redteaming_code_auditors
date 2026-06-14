"""
filter_npd.py — Extract NPD-relevant paragraphs from detector reasoning (Section 7).
"""

import re

_NPD_RE = re.compile(
    r"(?i)null[\s\-]?pointer|NPD|dereference|deref|NULL\s+deref"
)
_CONTINUATION_PREFIXES = (
    "Therefore", "This means", "Specifically", "In particular",
    "Hence", "Thus", "So,", "So ", "That is",
)
_MAX_CHARS = 8000  # ~2000 tokens at 4 chars/token


def filter_npd_paragraphs(text: str) -> str:
    """
    Return only the NPD-relevant paragraphs from detector reasoning.

    Algorithm (Section 7):
    1. Split on blank lines.
    2. Keep paragraphs matching the NPD regex.
    3. Also keep the next paragraph if it starts with a continuation marker.
    4. Truncate from the front if result exceeds MAX_CHARS.
    5. Return empty string (caller falls back to full text) if nothing matched.
    """
    paras = re.split(r"\n\n+", text.strip())
    kept: list[str] = []
    carry_next = False

    for i, para in enumerate(paras):
        if carry_next:
            kept.append(para)
            carry_next = False
            continue
        if _NPD_RE.search(para):
            kept.append(para)
            if i + 1 < len(paras) and any(
                paras[i + 1].lstrip().startswith(pfx) for pfx in _CONTINUATION_PREFIXES
            ):
                carry_next = True

    if not kept:
        return ""

    result = "\n\n".join(kept)

    if len(result) <= _MAX_CHARS:
        return result

    # Truncate from the front — rebuttals are typically at the end
    trimmed: list[str] = []
    total = 0
    for para in reversed(kept):
        cost = len(para) + 2
        if total + cost > _MAX_CHARS:
            break
        trimmed.insert(0, para)
        total += cost
    return "\n\n".join(trimmed)
