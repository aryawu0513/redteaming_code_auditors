"""
annotation_utils.py — shared helpers for locating injected annotation comments
in C source files and recovering the NPD anchor (deref line) and target function.

Used by:
  build_eval_datasets.py  — to determine target_function split point and stamp
                            deref_line + caller into dataset JSONs
  adaptive/refine_loop.py — to detect the anchor at runtime when the dataset
                            record carries no deref_line field (legacy records)
"""

import re
from pathlib import Path

# C function definition at column 0, e.g. "int compute_value(" or "Node* reverse("
_FUNC_DEF_RE = re.compile(r'^(?:static\s+)?(?:[\w\*]+\s+)+(\w+)\s*\(', re.MULTILINE)
_MAIN_RE = re.compile(r'^(?:int|void)\s+main\s*\(', re.MULTILINE)


# ── Anchor detection (deref line) ─────────────────────────────────────────────

def first_code_after_comment(target_function: str) -> str | None:
    """Return the first non-empty, non-comment line that immediately follows
    any comment block in target_function.

    This is the NPD deref line for all between_call_and_deref attack types
    (AA_CA, AA_MSG, FT, COT, CG, TOOL_*).
    """
    lines = target_function.split("\n")
    in_block = False
    comment_seen = False
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if "/*" in s:
            in_block = True
        if "*/" in s:
            in_block = False
            comment_seen = True
            continue
        is_comment = in_block or s.startswith("//") or s.startswith("/*") or s.startswith("*")
        if is_comment:
            comment_seen = True
            continue
        if comment_seen:
            return s
    return None


def anchor_from_aa_usr(target_function: str) -> str | None:
    """AA_USR appends '  // USER: ...' onto the deref line itself.
    Return the code portion of that line (stripped of the trailing comment)."""
    for line in target_function.split("\n"):
        if "// USER:" in line:
            prefix = line[: line.index("// USER:")].strip()
            return prefix or None
    return None


def vote_anchor(target_functions: list[str]) -> str | None:
    """Majority-vote the NPD deref line (anchor) across multiple target_function
    strings (one per attack type for the same slug).

    Each between_call_and_deref record contributes via first_code_after_comment;
    AA_USR records contribute via anchor_from_aa_usr.  The most common non-empty
    candidate wins.
    """
    votes: dict[str, int] = {}
    for tf in target_functions:
        cand = anchor_from_aa_usr(tf) if "// USER:" in tf else first_code_after_comment(tf)
        if cand:
            votes[cand] = votes.get(cand, 0) + 1
    return max(votes, key=votes.__getitem__) if votes else None


# ── Target function detection (builder use) ───────────────────────────────────

def annotated_function(source: str) -> tuple[str | None, int | None]:
    """Given a full C source file, return (function_name, char_offset) of the
    function containing an injected annotation comment (any attack type).

    Searches for a comment block (// or /* */) that immediately precedes a
    non-comment code line, then walks backward to the enclosing function def.
    Returns (None, None) if no annotation site is found.
    """
    lines = source.split("\n")
    # Find the first line that follows a comment block (= deref site)
    in_block = False
    comment_seen = False
    deref_line_idx = None
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        if "/*" in s:
            in_block = True
        if "*/" in s:
            in_block = False
            comment_seen = True
            continue
        is_comment = in_block or s.startswith("//") or s.startswith("/*") or s.startswith("*")
        if is_comment:
            comment_seen = True
            continue
        if comment_seen:
            deref_line_idx = i
            break

    if deref_line_idx is None:
        return None, None

    # Walk backward from the deref line to find the enclosing function definition.
    for i in range(deref_line_idx - 1, -1, -1):
        m = _FUNC_DEF_RE.match(lines[i])
        if m:
            offset = sum(len(l) + 1 for l in lines[:i])
            return m.group(1), offset

    return None, None


def vote_annotated_function(solution_files: list[Path]) -> tuple[str, int]:
    """Majority-vote the target function across all solution_*.c files for a slug.

    Each file votes for the (function_name, char_offset) pair detected by
    annotated_function().  The most-voted function_name wins; its offset is
    taken from the CLEAN solution (or the first file that agrees on the name).

    Falls back to main() if no annotation is detected in any file.
    """
    name_votes: dict[str, int] = {}
    name_to_offset: dict[str, int] = {}

    for path in solution_files:
        try:
            source = path.read_text()
        except OSError:
            continue
        fn_name, offset = annotated_function(source)
        if fn_name is None:
            continue
        name_votes[fn_name] = name_votes.get(fn_name, 0) + 1
        if fn_name not in name_to_offset:
            name_to_offset[fn_name] = offset

    if not name_votes:
        return "main", _fallback_main_offset(solution_files)

    winner = max(name_votes, key=name_votes.__getitem__)
    return winner, name_to_offset[winner]


def _fallback_main_offset(solution_files: list[Path]) -> int:
    for path in solution_files:
        try:
            source = path.read_text()
        except OSError:
            continue
        m = _MAIN_RE.search(source)
        if m:
            return m.start()
    return 0
