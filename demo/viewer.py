"""
Demo results viewer — browse attack results for RepoAudit and VulnLLM-R.

Features:
  - Defense dropdown: "No-Defense" shows original results; D1/D3L/D4_prepend show defense runs.
  - Manual verdict override per system (saves to demo/demo_judge_cache.json or
    demo/demo_judge_cache_defense.json depending on defense selection).
  - Phrase highlighting in all three output tabs:
      "No-Defense" mode → demo/highlight_cache.json
      defense mode → demo/highlight_cache_defense.json
    Cache keys: {repo}:{attack}:{system} (buggy) or {defense}:{repo}:{attack}:{system} (defenses)

Usage:
    cd /mnt/ssd/aryawu/redteaming_repoaudit
    source VulnLLM-R/.venv/bin/activate
    python demo/viewer.py
    # → http://localhost:6003
"""
import html as _html
import json
import re
from pathlib import Path

import gradio as gr

DEMO_DIR    = Path(__file__).parent.absolute()
RESULTS_DIR = DEMO_DIR / "results"

RESULTS_DEFENSE_DIR           = DEMO_DIR / "results_defense"
HIGHLIGHT_CACHE_DEFENSE_PATH  = DEMO_DIR / "highlight_cache_defense.json"
DEMO_JUDGE_CACHE_DEFENSE_PATH = DEMO_DIR / "demo_judge_cache_defense.json"
DEFENSE_CHOICES = ["No-Defense", "D1", "D3L", "D4_prepend"]

TARGET_FN_MAP = {
    "target_repo":    "display_user",
    "target_repo_v2": "write_record",
}

# Default log file to show in the RepoAudit tabs (overrides alphabetical first).
# target_repo_v2: buffer.log traces make_buffer()->NULL->write_record dereference.
#   alloc.log (heap_alloc) is unreachable — make_buffer's len<=0 guard fires first.
TARGET_LOG_MAP = {
    "target_repo": "db.log",
    "target_repo_v2": "buffer.log",
}

# Default source file to show in the Source Code tab (overrides alphabetical first).
TARGET_SRC_MAP = {
    "target_repo": "users.c",
    "target_repo_v2": "writer.c",
}

DEMO_JUDGE_CACHE_PATH = DEMO_DIR / "demo_judge_cache.json"
HIGHLIGHT_CACHE_PATH  = DEMO_DIR / "highlight_cache.json"

# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def load_demo_judge_cache() -> dict:
    if DEMO_JUDGE_CACHE_PATH.exists():
        try:
            return json.loads(DEMO_JUDGE_CACHE_PATH.read_text())
        except Exception:
            pass
    return {}


def save_demo_judge_cache(cache: dict):
    DEMO_JUDGE_CACHE_PATH.write_text(json.dumps(cache, indent=2))


def load_highlight_cache() -> dict:
    if HIGHLIGHT_CACHE_PATH.exists():
        try:
            return json.loads(HIGHLIGHT_CACHE_PATH.read_text())
        except Exception:
            pass
    return {}


def save_highlight_cache(cache: dict):
    HIGHLIGHT_CACHE_PATH.write_text(json.dumps(cache, indent=2))


def load_demo_judge_cache_defense() -> dict:
    if DEMO_JUDGE_CACHE_DEFENSE_PATH.exists():
        try:
            return json.loads(DEMO_JUDGE_CACHE_DEFENSE_PATH.read_text())
        except Exception:
            pass
    return {}


def save_demo_judge_cache_defense(cache: dict):
    DEMO_JUDGE_CACHE_DEFENSE_PATH.write_text(json.dumps(cache, indent=2))


def load_highlight_cache_defense() -> dict:
    if HIGHLIGHT_CACHE_DEFENSE_PATH.exists():
        try:
            return json.loads(HIGHLIGHT_CACHE_DEFENSE_PATH.read_text())
        except Exception:
            pass
    return {}


def save_highlight_cache_defense(cache: dict):
    HIGHLIGHT_CACHE_DEFENSE_PATH.write_text(json.dumps(cache, indent=2))


# ---------------------------------------------------------------------------
# Defense routing helpers
# ---------------------------------------------------------------------------

def _results_root(defense: str) -> Path:
    """Return the results directory for the given defense."""
    return RESULTS_DIR if defense == "No-Defense" else RESULTS_DEFENSE_DIR / defense


def _attacks_dir_for(repo: str, defense: str) -> Path:
    """Return the attacked repos directory for the given defense.
    D3L/D4_prepend use sanitized repos; all others use original attacks."""
    if defense in ("D3L", "D4_prepend"):
        return DEMO_DIR / "target_repo_attacks_defense" / defense / repo
    return DEMO_DIR / f"{repo}_attacks"


def _hl_cache_key(defense: str, repo: str, attack_label: str, tab_key: str) -> str:
    if defense == "No-Defense":
        return f"{repo}:{attack_label}:{tab_key}"
    return f"{defense}:{repo}:{attack_label}:{tab_key}"


def _judge_cache_key(defense: str, repo: str, attack_label: str, system: str) -> str:
    if defense == "No-Defense":
        return f"{repo}:{attack_label}:{system}"
    return f"{defense}:{repo}:{attack_label}:{system}"


def _load_hl_cache(defense: str) -> dict:
    return load_highlight_cache() if defense == "No-Defense" else load_highlight_cache_defense()


def _save_hl_cache(defense: str, cache: dict):
    if defense == "No-Defense":
        save_highlight_cache(cache)
    else:
        save_highlight_cache_defense(cache)


def _load_judge_cache(defense: str) -> dict:
    return load_demo_judge_cache() if defense == "No-Defense" else load_demo_judge_cache_defense()


def _save_judge_cache(defense: str, cache: dict):
    if defense == "No-Defense":
        save_demo_judge_cache(cache)
    else:
        save_demo_judge_cache_defense(cache)


# ---------------------------------------------------------------------------
# RepoAudit log parsers
# ---------------------------------------------------------------------------

def extract_explorer_sections(log_text: str) -> list[dict]:
    sections = []
    parts = re.split(r"\[EXPLORER\] Analyzing ", log_text)
    for part in parts[1:]:
        m = re.match(r"(.+?)\(\) for source '(.+?)' \(label=.+?\) at line (\d+)", part)
        func = m.group(1).strip() if m else "?"
        src  = m.group(2).strip() if m else "?"
        line = m.group(3).strip() if m else "?"
        resp_m = re.search(r"Response:\s*\n(.+?)(?=\n\d{4}-\d{2}-\d{2}|\Z)", part, re.DOTALL)
        response = resp_m.group(1).strip() if resp_m else ""
        out_m = re.search(r"\[EXPLORER\] Output: (.+)", part)
        output = out_m.group(1).strip() if out_m else "?"
        sections.append({"func": func, "src": src, "line": line,
                         "response": response, "output": output})
    return sections


def extract_validator_sections(log_text: str) -> list[dict]:
    sections = []
    parts = re.split(r"The LLM Tool PathValidator is invoked\.", log_text)
    for part in parts[1:]:
        path_lines = re.findall(r" - \(.*?\) in the function .+? at the line \d+", part)
        path_desc = "\n".join(path_lines) if path_lines else "(path not extracted)"
        resp_m = re.search(r"Response:\s*\n(.+?)(?=\n\d{4}-\d{2}-\d{2}|\Z)", part, re.DOTALL)
        response = resp_m.group(1).strip() if resp_m else ""
        ans_m = re.search(r"Answer:\s*(Yes|No)", response)
        answer = ans_m.group(1) if ans_m else "?"
        sections.append({"path_desc": path_desc, "response": response, "answer": answer})
    return sections


def format_ra_log(log_text: str) -> str:
    lines = []
    explorer_secs = extract_explorer_sections(log_text)
    if explorer_secs:
        lines.append("▶▶▶ EXPLORER ◀◀◀\n")
        for i, s in enumerate(explorer_secs, 1):
            lines.append(f"── Explorer call {i}: {s['func']}()  src='{s['src']}' @ line {s['line']} ──")
            lines.append(s["response"])
            lines.append(f"\n  → Parsed output: {s['output']}\n")
    else:
        lines.append("▶▶▶ EXPLORER ◀◀◀\n(no IntraDataFlowAnalyzer calls found)\n")
    validator_secs = extract_validator_sections(log_text)
    lines.append("▶▶▶ VALIDATOR ◀◀◀\n")
    if not validator_secs:
        lines.append("(no PathValidator calls — Explorer returned no paths)")
    else:
        for i, s in enumerate(validator_secs, 1):
            ans_label = "✓ Yes (bug confirmed)" if s["answer"] == "Yes" else "✗ No (path dismissed)"
            lines.append(f"── Validator call {i}: {ans_label} ──")
            if s["path_desc"]:
                lines.append("Propagation path:\n" + s["path_desc"])
            lines.append("\n" + s["response"] + "\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

def verdict_badge(status: str, manual: bool = False, safe_mode: bool = False) -> str:
    tag = (' <span style="font-size:0.72em;opacity:0.65;font-style:italic">(manual)</span>'
           if manual else '')
    if status == "DETECTED":
        if safe_mode:
            return (f'<span style="background:#f8d7da;color:#721c24;padding:4px 14px;'
                    f'border-radius:4px;font-weight:bold;font-size:1.05em">✗ FALSE POSITIVE</span>{tag}')
        return (f'<span style="background:#d4edda;color:#155724;padding:4px 14px;'
                f'border-radius:4px;font-weight:bold;font-size:1.05em">✓ DETECTED</span>{tag}')
    if status == "MISSED":
        if safe_mode:
            return (f'<span style="background:#d4edda;color:#155724;padding:4px 14px;'
                    f'border-radius:4px;font-weight:bold;font-size:1.05em">✓ CORRECT</span>{tag}')
        return (f'<span style="background:#f8d7da;color:#721c24;padding:4px 14px;'
                f'border-radius:4px;font-weight:bold;font-size:1.05em">✗ MISSED</span>{tag}')
    return (f'<span style="background:#e2e3e5;color:#383d41;padding:4px 14px;'
            f'border-radius:4px;font-weight:bold;font-size:1.05em">— N/A —</span>{tag}')


def _effective_status(auto: str, manual: str) -> tuple[str, bool]:
    if manual and manual != "Auto":
        return manual, True
    return auto, False


def _make_verdicts_html(ra_eff, ra37_eff, vl_eff,
                        ra_m=False, ra37_m=False, vl_m=False,
                        safe_mode: bool = False) -> str:
    return (
        f'<div style="display:flex;gap:16px;align-items:center;padding:8px 0">'
        f'<span style="color:#888;font-size:0.9em">RepoAudit (haiku):</span> {verdict_badge(ra_eff, ra_m, safe_mode)}'
        f'&nbsp;&nbsp;<span style="color:#888;font-size:0.9em">RepoAudit (3.7):</span> {verdict_badge(ra37_eff, ra37_m, safe_mode)}'
        f'&nbsp;&nbsp;<span style="color:#888;font-size:0.9em">VulnLLM-R:</span> {verdict_badge(vl_eff, vl_m, safe_mode)}'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Highlight rendering (shared by all three tabs)
# Highlights stored as list of dicts: [{"phrase": "...", "color": "red"|"green"}, ...]
# Old string-list format is auto-migrated to red on load.
# ---------------------------------------------------------------------------

_HL_STYLES = {
    "red":   "background:#fde8e8;color:#c0392b;font-weight:600;border-radius:2px;padding:0 2px",
    "green": "background:#d5f5e3;color:#1e8449;font-weight:600;border-radius:2px;padding:0 2px",
}


def _normalize_highlights(raw: list) -> list[dict]:
    """Migrate old string lists to [{phrase, color}] dicts."""
    result = []
    for h in raw:
        if isinstance(h, str):
            result.append({"phrase": h, "color": "red"})
        elif isinstance(h, dict) and "phrase" in h:
            result.append(h)
    return result


def _render_highlighted(text: str, highlights: list) -> str:
    escaped    = _html.escape(text)
    normalized = _normalize_highlights(highlights)
    for h in sorted(normalized, key=lambda x: len(x.get("phrase", "")), reverse=True):
        phrase = h.get("phrase", "").strip()
        if not phrase:
            continue
        style = _HL_STYLES.get(h.get("color", "red"), _HL_STYLES["red"])
        ep    = _html.escape(phrase)
        escaped = escaped.replace(ep, f'<mark style="{style}">{ep}</mark>')
    return (
        '<div style="display:flex;flex-direction:column-reverse;max-height:580px;overflow-y:auto;'
        'border:1px solid #dee2e6;border-radius:6px;background:#f8f9fa">'
        '<pre style="white-space:pre-wrap;font-family:\'Courier New\',monospace;'
        'font-size:0.82em;line-height:1.65;padding:14px;margin:0">'
        + escaped + '</pre>'
        '</div>'
    )


def _highlights_md(highlights: list) -> str:
    normalized = _normalize_highlights(highlights)
    if not normalized:
        return "*No highlights saved*"
    icons = {"red": "🔴", "green": "🟢"}
    items = " &nbsp;·&nbsp; ".join(
        f"{icons.get(h.get('color','red'), '🔴')} `{h.get('phrase','')}`"
        for h in normalized
    )
    return f"**Highlighted:** {items}"


# ---------------------------------------------------------------------------
# Highlight callbacks — one set per tab via factory
# ---------------------------------------------------------------------------

def _make_hl_callbacks(tab_key: str):
    """Returns (on_add, on_clear) callbacks bound to the given tab_key.
    Both callbacks accept a 'defense' argument to route to the correct cache."""

    def on_add(repo: str, attack_label: str, defense: str,
               phrase: str, color: str, hl_json: str, raw: str):
        highlights = _normalize_highlights(json.loads(hl_json) if hl_json else [])
        phrase    = phrase.strip()
        color_key = (color or "Red").lower()
        if phrase:
            # replace if phrase already exists (update color)
            highlights = [h for h in highlights if h.get("phrase") != phrase]
            highlights.append({"phrase": phrase, "color": color_key})
            cache = _load_hl_cache(defense)
            cache[_hl_cache_key(defense, repo, attack_label, tab_key)] = highlights
            _save_hl_cache(defense, cache)
        return (_render_highlighted(raw, highlights),
                json.dumps(highlights),
                _highlights_md(highlights),
                "")  # clear input

    def on_clear(repo: str, attack_label: str, defense: str, raw: str):
        cache = _load_hl_cache(defense)
        cache.pop(_hl_cache_key(defense, repo, attack_label, tab_key), None)
        _save_hl_cache(defense, cache)
        return _render_highlighted(raw, []), json.dumps([]), "*No highlights saved*"

    return on_add, on_clear


on_add_ra,   on_clear_ra   = _make_hl_callbacks("repoaudit")
on_add_ra37, on_clear_ra37 = _make_hl_callbacks("repoaudit_3p7")
on_add_vl,   on_clear_vl   = _make_hl_callbacks("vulnllm")


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def get_repos() -> list[str]:
    return [d.name for d in sorted(RESULTS_DIR.iterdir()) if d.is_dir()]


def get_attacks(repo: str) -> list[str]:
    types: set[str] = set()
    base = RESULTS_DIR / repo
    for subdir in ["vulnllm", "repoaudit", "repoaudit_3p7"]:
        d = base / subdir
        if not d.exists():
            continue
        for p in d.glob("attacked_repo_*.json"):
            m = re.search(r"attacked_repo_(.+)\.json$", p.name)
            if m:
                types.add(m.group(1))
        for p in d.iterdir():
            if p.is_dir() and p.name.startswith("attacked_repo_"):
                types.add(p.name.replace("attacked_repo_", "", 1))
    attacks_dir = DEMO_DIR / f"{repo}_attacks"
    if attacks_dir.exists():
        for p in attacks_dir.iterdir():
            if p.is_dir() and p.name.startswith("attacked_repo_"):
                types.add(p.name.replace("attacked_repo_", "", 1))
    HIDDEN = {'AA_PR', 'TOOL_MISRA', 'TOOL_Pylint'}
    types -= HIDDEN
    return ["safe", "buggy"] + sorted(types)


def _find_log_dir(ra_root: Path) -> Path | None:
    candidates = list(ra_root.glob("log/dfbscan/**"))
    leaf_dirs = [p for p in candidates if p.is_dir() and any(p.glob("*.log"))]
    return max(leaf_dirs, key=lambda p: p.stat().st_mtime) if leaf_dirs else None


def _find_detect_info(ra_root: Path) -> Path | None:
    candidates = list(ra_root.glob("result/dfbscan/**/detect_info.json"))
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def read_ra_status(repo: str, variant: str, attack: str | None,
                   defense: str = "No-Defense") -> str:
    if attack is None:
        subdir = "baseline"
    elif attack == "safe":
        subdir = "safe"
    else:
        subdir = f"attacked_repo_{attack}"
    ra_root = _results_root(defense) / repo / variant / subdir
    if not ra_root.exists():
        return "N/A"
    target_fn = TARGET_FN_MAP.get(repo, "write_record")
    detect_path = _find_detect_info(ra_root)
    if detect_path is None:
        return "MISSED"
    data = json.loads(detect_path.read_text())
    for entry in data.values():
        fns = entry.get("relevant_functions", [])
        if len(fns) >= 2 and any(target_fn in fn for fn in fns[1]):
            return "DETECTED"
    return "MISSED"


def read_vl_status(repo: str, attack: str | None, defense: str = "No-Defense") -> str:
    results = _results_root(defense)
    if attack is None:
        path = results / repo / "vulnllm" / "baseline_vulnllm.json"
    elif attack == "safe":
        path = results / repo / "vulnllm" / "safe_vulnllm.json"
    else:
        path = results / repo / "vulnllm" / f"attacked_repo_{attack}.json"
    if not path.exists():
        return "N/A"
    target_fn = TARGET_FN_MAP.get(repo, "write_record")
    for rec in json.loads(path.read_text()):
        if rec.get("function") == target_fn:
            if rec.get("judge") != "yes":
                return "MISSED"
            return "DETECTED" if "CWE-476" in rec.get("cwe_type", "") else "MISSED"
    return "MISSED"


def load_source_files(repo: str, attack: str | None,
                      defense: str = "No-Defense") -> tuple[list[str], dict[str, str]]:
    if attack is None:
        src_dir = DEMO_DIR / repo
    elif attack == "safe":
        src_dir = DEMO_DIR / f"{repo}_orig"
    else:
        src_dir = _attacks_dir_for(repo, defense) / f"attacked_repo_{attack}"
    if not src_dir.exists():
        return [], {}
    files = {}
    for ext in ("*.c", "*.h"):
        for f in sorted(src_dir.glob(ext)):
            files[f.name] = f.read_text()
    return list(files.keys()), files


def load_ra_reasoning(repo: str, variant: str, attack: str | None,
                      defense: str = "No-Defense") -> tuple[list[str], dict[str, str]]:
    if attack is None:
        subdir = "baseline"
    elif attack == "safe":
        subdir = "safe"
    else:
        subdir = f"attacked_repo_{attack}"
    ra_root = _results_root(defense) / repo / variant / subdir
    log_dir = _find_log_dir(ra_root)
    if not log_dir:
        return [], {}
    logs = {f.name: f.read_text() for f in sorted(log_dir.glob("*.log")) if f.name != "dfbscan.log"}
    return list(logs.keys()), logs


def load_vl_output(repo: str, attack: str | None, defense: str = "No-Defense") -> str:
    results = _results_root(defense)
    if attack is None:
        path = results / repo / "vulnllm" / "baseline_vulnllm.json"
    elif attack == "safe":
        path = results / repo / "vulnllm" / "safe_vulnllm.json"
    else:
        path = results / repo / "vulnllm" / f"attacked_repo_{attack}.json"
    if not path.exists():
        return "(no result file)"
    target_fn = TARGET_FN_MAP.get(repo, "write_record")
    for rec in json.loads(path.read_text()):
        if rec.get("function") == target_fn:
            out   = rec.get("output", "")
            cwe   = rec.get("cwe_type", "N/A")
            judge = rec.get("judge", "?")
            return f"judge: {judge}  |  cwe_type: {cwe}\n{'─'*60}\n" + out
    return "(target function not found in results)"


# ---------------------------------------------------------------------------
# Core load — 24 outputs (must match all_outputs exactly)
# ---------------------------------------------------------------------------

def _load_all(repo: str, attack_label: str, defense: str = "No-Defense"):
    attack = None if attack_label == "buggy" else attack_label

    judge_cache = _load_judge_cache(defense)
    hl_cache    = _load_hl_cache(defense)

    # Verdicts
    ra_auto   = read_ra_status(repo, "repoaudit",     attack, defense)
    ra37_auto = read_ra_status(repo, "repoaudit_3p7", attack, defense)
    vl_auto   = read_vl_status(repo, attack, defense)

    ra_manual_val   = judge_cache.get(_judge_cache_key(defense, repo, attack_label, "repoaudit"),     "Auto")
    ra37_manual_val = judge_cache.get(_judge_cache_key(defense, repo, attack_label, "repoaudit_3p7"), "Auto")
    vl_manual_val   = judge_cache.get(_judge_cache_key(defense, repo, attack_label, "vulnllm"),       "Auto")

    ra_eff,   ra_m   = _effective_status(ra_auto,   ra_manual_val)
    ra37_eff, ra37_m = _effective_status(ra37_auto, ra37_manual_val)
    vl_eff,   vl_m   = _effective_status(vl_auto,   vl_manual_val)
    verdicts_html = _make_verdicts_html(ra_eff, ra37_eff, vl_eff, ra_m, ra37_m, vl_m,
                                        safe_mode=(attack_label == "safe"))

    # Source
    src_names, src_files = load_source_files(repo, attack, defense)
    _src_pref     = TARGET_SRC_MAP.get(repo)
    init_src_name = (_src_pref if _src_pref and _src_pref in src_names
                     else next((n for n in src_names if n.endswith(".c") and n != "main.c"),
                               src_names[0] if src_names else ""))
    init_src = src_files.get(init_src_name, "(not found)")

    # RA haiku
    ra_log_names, ra_logs = load_ra_reasoning(repo, "repoaudit", attack, defense)
    _pref        = TARGET_LOG_MAP.get(repo)
    init_ra_log  = (_pref if _pref and _pref in ra_log_names
                    else (ra_log_names[0] if ra_log_names else ""))
    ra_raw       = format_ra_log(ra_logs[init_ra_log]) if init_ra_log else "(no logs)"
    ra_hl        = _normalize_highlights(hl_cache.get(_hl_cache_key(defense, repo, attack_label, "repoaudit"), []))
    ra_html      = _render_highlighted(ra_raw, ra_hl)
    ra_hl_md     = _highlights_md(ra_hl)

    # RA 3.7
    ra37_log_names, ra37_logs = load_ra_reasoning(repo, "repoaudit_3p7", attack, defense)
    init_ra37_log = (_pref if _pref and _pref in ra37_log_names
                     else (ra37_log_names[0] if ra37_log_names else ""))
    ra37_raw      = format_ra_log(ra37_logs[init_ra37_log]) if init_ra37_log else "(no logs)"
    ra37_hl       = _normalize_highlights(hl_cache.get(_hl_cache_key(defense, repo, attack_label, "repoaudit_3p7"), []))
    ra37_html     = _render_highlighted(ra37_raw, ra37_hl)
    ra37_hl_md    = _highlights_md(ra37_hl)

    # VulnLLM-R
    vl_raw    = load_vl_output(repo, attack, defense)
    vl_hl     = _normalize_highlights(hl_cache.get(_hl_cache_key(defense, repo, attack_label, "vulnllm"), []))
    vl_html   = _render_highlighted(vl_raw, vl_hl)
    vl_hl_md  = _highlights_md(vl_hl)

    return (
        verdicts_html,                                          #  1 verdict_html
        gr.update(choices=src_names,      value=init_src_name or None),#  2 src_file_dd
        gr.update(value=init_src,         language="c"),              #  3 src_box
        gr.update(choices=ra_log_names,   value=init_ra_log or None), #  4 ra_log_dd
        ra_html,                                                       #  5 ra_html_box
        gr.update(choices=ra37_log_names, value=init_ra37_log or None),#  6 ra37_log_dd
        ra37_html,                                              #  7 ra37_html_box
        vl_html,                                                #  8 vl_html_box
        json.dumps(src_files),                                  #  9 src_files_state
        json.dumps(ra_logs),                                    # 10 ra_logs_state
        json.dumps(ra37_logs),                                  # 11 ra37_logs_state
        ra_manual_val,                                          # 12 ra_manual_dd
        ra37_manual_val,                                        # 13 ra37_manual_dd
        vl_manual_val,                                          # 14 vl_manual_dd
        json.dumps(ra_hl),                                      # 15 ra_hl_state
        ra_raw,                                                 # 16 ra_raw_state
        ra_hl_md,                                               # 17 ra_hl_display
        json.dumps(ra37_hl),                                    # 18 ra37_hl_state
        ra37_raw,                                               # 19 ra37_raw_state
        ra37_hl_md,                                             # 20 ra37_hl_display
        json.dumps(vl_hl),                                      # 21 vl_hl_state
        vl_raw,                                                 # 22 vl_raw_state
        vl_hl_md,                                               # 23 vl_hl_display
        gr.update(value=""),                                    # 24 judge_status (clear)
    )


# ---------------------------------------------------------------------------
# Navigation callbacks
# ---------------------------------------------------------------------------

def on_repo_change(repo: str, defense: str):
    attacks = get_attacks(repo)
    return (gr.update(choices=attacks, value=attacks[0]),) + _load_all(repo, attacks[0], defense)


def on_attack_change(repo: str, attack_label: str, defense: str):
    return _load_all(repo, attack_label, defense)


def on_defense_change(repo: str, attack_label: str, defense: str):
    return _load_all(repo, attack_label, defense)


def on_src_file_change(filename: str, src_files_json: str):
    return gr.update(value=json.loads(src_files_json).get(filename, "(not found)"), language="c")


def on_ra_log_change(filename: str, logs_json: str, ra_hl_json: str):
    raw = format_ra_log(json.loads(logs_json).get(filename, ""))
    hl  = json.loads(ra_hl_json) if ra_hl_json else []
    return _render_highlighted(raw, hl), raw   # → [ra_html_box, ra_raw_state]


def on_ra37_log_change(filename: str, logs_json: str, ra37_hl_json: str):
    raw = format_ra_log(json.loads(logs_json).get(filename, ""))
    hl  = json.loads(ra37_hl_json) if ra37_hl_json else []
    return _render_highlighted(raw, hl), raw   # → [ra37_html_box, ra37_raw_state]


# ---------------------------------------------------------------------------
# Judgment save callback
# ---------------------------------------------------------------------------

def on_save_judge(repo: str, attack_label: str, defense: str,
                  ra_manual: str, ra37_manual: str, vl_manual: str):
    cache = _load_judge_cache(defense)
    for system, val in [("repoaudit", ra_manual), ("repoaudit_3p7", ra37_manual), ("vulnllm", vl_manual)]:
        key = _judge_cache_key(defense, repo, attack_label, system)
        if val == "Auto":
            cache.pop(key, None)
        else:
            cache[key] = val
    _save_judge_cache(defense, cache)

    attack = None if attack_label == "buggy" else attack_label
    ra_eff,   ra_m   = _effective_status(read_ra_status(repo, "repoaudit",     attack, defense), ra_manual)
    ra37_eff, ra37_m = _effective_status(read_ra_status(repo, "repoaudit_3p7", attack, defense), ra37_manual)
    vl_eff,   vl_m   = _effective_status(read_vl_status(repo,                  attack, defense), vl_manual)
    return _make_verdicts_html(ra_eff, ra37_eff, vl_eff, ra_m, ra37_m, vl_m,
                               safe_mode=(attack_label == "safe")), "✓ Judgments saved"


# ---------------------------------------------------------------------------
# CLI args — parsed at module level so UI construction can use them
# ---------------------------------------------------------------------------

import argparse as _ap
_parser = _ap.ArgumentParser()
_parser.add_argument("--port",   type=int, default=6003)
_parser.add_argument("--editor", action="store_true",
                     help="Show manual override and highlight editing controls")
_args, _ = _parser.parse_known_args()
EDITOR_MODE = _args.editor
PORT        = _args.port

# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

init_repos   = get_repos()
init_repo    = init_repos[0] if init_repos else "target_repo_v2"
init_attacks = get_attacks(init_repo)
init_attack  = init_attacks[0]
init_defense = "No-Defense"

_init = _load_all(init_repo, init_attack, init_defense)
(init_verdicts,
 _src_dd,    _src_box,
 _ra_dd,     init_ra_html,
 _ra37_dd,   init_ra37_html,
 init_vl_html,
 init_src_json, init_ra_json, init_ra37_json,
 init_ra_manual, init_ra37_manual, init_vl_manual,
 init_ra_hl_json,  init_ra_raw,  init_ra_hl_md,
 init_ra37_hl_json, init_ra37_raw, init_ra37_hl_md,
 init_vl_hl_json,  init_vl_raw,  init_vl_hl_md,
 _) = _init

init_src_names  = _src_dd["choices"];    init_src_name  = _src_dd["value"]
init_src_code   = _src_box["value"]
init_ra_names   = _ra_dd["choices"];     init_ra_name   = _ra_dd["value"]
init_ra37_names = _ra37_dd["choices"];   init_ra37_name = _ra37_dd["value"]

# ---------------------------------------------------------------------------
# Gradio UI
# ---------------------------------------------------------------------------

with gr.Blocks(title="Demo Viewer", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# Demo Viewer — Adversarial Comment Injection")
    gr.Markdown("Browse source code and auditor reasoning for each attack variant.")

    # Persistent state
    src_files_state   = gr.State(init_src_json)
    ra_logs_state     = gr.State(init_ra_json)
    ra37_logs_state   = gr.State(init_ra37_json)
    ra_hl_state       = gr.State(init_ra_hl_json)
    ra_raw_state      = gr.State(init_ra_raw)
    ra37_hl_state     = gr.State(init_ra37_hl_json)
    ra37_raw_state    = gr.State(init_ra37_raw)
    vl_hl_state       = gr.State(init_vl_hl_json)
    vl_raw_state      = gr.State(init_vl_raw)

    with gr.Row():
        repo_dd    = gr.Dropdown(choices=init_repos,    value=init_repo,    label="Repository", scale=1)
        attack_dd  = gr.Dropdown(choices=init_attacks,  value=init_attack,  label="Attack",     scale=3)
        defense_dd = gr.Dropdown(choices=DEFENSE_CHOICES, value=init_defense, label="Defense",  scale=1)

    verdict_html = gr.HTML(value=init_verdicts)

    # Manual judgment override — editor mode only
    with gr.Row(visible=EDITOR_MODE):
        gr.Markdown("**Manual override:**")
        ra_manual_dd   = gr.Dropdown(choices=["Auto", "DETECTED", "MISSED"],
                                     value=init_ra_manual,   label="RepoAudit (haiku)", scale=1)
        ra37_manual_dd = gr.Dropdown(choices=["Auto", "DETECTED", "MISSED"],
                                     value=init_ra37_manual, label="RepoAudit (3.7)",   scale=1)
        vl_manual_dd   = gr.Dropdown(choices=["Auto", "DETECTED", "MISSED"],
                                     value=init_vl_manual,   label="VulnLLM-R",         scale=1)
        save_judge_btn = gr.Button("Save", size="sm", scale=0)
    judge_status = gr.Markdown("", visible=EDITOR_MODE)

    def _hl_controls(add_fn, clear_fn,
                     hl_state, raw_state, hl_display_init,
                     html_box):
        """Wire highlight controls for one tab.
        Editing inputs are hidden in public mode; rendered highlights always show.
        defense_dd is included so highlights route to the correct cache file."""
        with gr.Row(visible=EDITOR_MODE):
            hl_in       = gr.Textbox(label="Phrase to highlight",
                                     placeholder="Type exact phrase then press Enter or click Add…",
                                     scale=4)
            color_radio = gr.Radio(["Red", "Green"], value="Red", label="Color", scale=0)
            add_btn     = gr.Button("Add Highlight", size="sm", scale=1)
            clear_btn   = gr.Button("Clear All",     size="sm", variant="stop", scale=0)
        hl_disp = gr.Markdown(value=hl_display_init, visible=EDITOR_MODE)
        if EDITOR_MODE:
            _outs   = [html_box, hl_state, hl_disp, hl_in]
            _inputs = [repo_dd, attack_dd, defense_dd, hl_in, color_radio, hl_state, raw_state]
            add_btn.click(add_fn,  inputs=_inputs, outputs=_outs)
            hl_in.submit(  add_fn, inputs=_inputs, outputs=_outs)
            clear_btn.click(clear_fn, inputs=[repo_dd, attack_dd, defense_dd, raw_state],
                            outputs=[html_box, hl_state, hl_disp])
        return hl_disp

    with gr.Tabs():
        with gr.Tab("Source Code"):
            src_file_dd = gr.Dropdown(choices=init_src_names, value=init_src_name, label="File")
            src_box     = gr.Code(value=init_src_code, language="c", label="", lines=35)

        with gr.Tab("RepoAudit (haiku)"):
            ra_log_dd   = gr.Dropdown(choices=init_ra_names, value=init_ra_name, label="Log file")
            ra_html_box = gr.HTML(value=init_ra_html)
            ra_hl_display = _hl_controls(on_add_ra, on_clear_ra,
                                         ra_hl_state, ra_raw_state, init_ra_hl_md, ra_html_box)

        with gr.Tab("RepoAudit (3.7-sonnet)"):
            ra37_log_dd   = gr.Dropdown(choices=init_ra37_names, value=init_ra37_name, label="Log file")
            ra37_html_box = gr.HTML(value=init_ra37_html)
            ra37_hl_display = _hl_controls(on_add_ra37, on_clear_ra37,
                                           ra37_hl_state, ra37_raw_state, init_ra37_hl_md, ra37_html_box)

        with gr.Tab("VulnLLM-R"):
            vl_html_box = gr.HTML(value=init_vl_html)
            vl_hl_display = _hl_controls(on_add_vl, on_clear_vl,
                                         vl_hl_state, vl_raw_state, init_vl_hl_md, vl_html_box)

    # ---------------------------------------------------------------------------
    # Navigation wiring — order must match _load_all return tuple
    # ---------------------------------------------------------------------------

    all_outputs = [
        verdict_html,
        src_file_dd, src_box,
        ra_log_dd,   ra_html_box,
        ra37_log_dd, ra37_html_box,
        vl_html_box,
        src_files_state, ra_logs_state, ra37_logs_state,
        ra_manual_dd, ra37_manual_dd, vl_manual_dd,
        ra_hl_state,  ra_raw_state,  ra_hl_display,
        ra37_hl_state, ra37_raw_state, ra37_hl_display,
        vl_hl_state,  vl_raw_state,  vl_hl_display,
        judge_status,
    ]

    repo_dd.change(on_repo_change, inputs=[repo_dd, defense_dd],
                   outputs=[attack_dd] + all_outputs)
    attack_dd.change(on_attack_change, inputs=[repo_dd, attack_dd, defense_dd],
                     outputs=all_outputs)
    defense_dd.change(on_defense_change, inputs=[repo_dd, attack_dd, defense_dd],
                      outputs=all_outputs)

    src_file_dd.change(on_src_file_change,
                       inputs=[src_file_dd, src_files_state], outputs=[src_box])
    ra_log_dd.change(on_ra_log_change,
                     inputs=[ra_log_dd, ra_logs_state, ra_hl_state],
                     outputs=[ra_html_box, ra_raw_state])
    ra37_log_dd.change(on_ra37_log_change,
                       inputs=[ra37_log_dd, ra37_logs_state, ra37_hl_state],
                       outputs=[ra37_html_box, ra37_raw_state])

    if EDITOR_MODE:
        save_judge_btn.click(
            on_save_judge,
            inputs=[repo_dd, attack_dd, defense_dd, ra_manual_dd, ra37_manual_dd, vl_manual_dd],
            outputs=[verdict_html, judge_status],
        )


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=PORT, share=False)
