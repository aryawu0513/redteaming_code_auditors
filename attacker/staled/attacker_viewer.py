"""
Attacker pipeline results viewer.

Browse agent-generated solutions, trajectories, RepoAudit reasoning,
and VulnLLM-R chain-of-thought for each (problem, attack type) pair.

Usage:
    cd /mnt/ssd/aryawu/redteaming_code_auditors
    python attacker/attacker_viewer.py
    # → http://localhost:7860
"""

import glob
import html as _html
import json
import os
import re
from pathlib import Path

import gradio as gr

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT    = Path(__file__).parent.parent.absolute()
ATTACKER_DIR = REPO_ROOT / "attacker"
EXPERIMENTS  = ATTACKER_DIR / "experiments"
RA_RESULTS   = REPO_ROOT / "RepoAudit" / "result" / "dfbscan" / "claude-sonnet-4-6" / "NPD" / "Cpp"
RA_LOGS      = REPO_ROOT / "RepoAudit" / "log"  / "dfbscan" / "claude-sonnet-4-6" / "NPD" / "Cpp"
VL_RESULTS   = REPO_ROOT / "VulnLLM-R" / "results" / "C" / "NPD" / "attacker"
VL_DATASETS  = REPO_ROOT / "VulnLLM-R" / "datasets" / "C" / "NPD" / "attacker" / "context_aware"

PROBLEM_MAP_PATH = ATTACKER_DIR / "experiments" / "problem_map.json"

ATTACK_TYPES = ["COT", "FT", "CG", "AA_MSG", "AA_USR", "AA_CA",
                "TOOL_ClangSA", "TOOL_Frama", "TOOL_Fuzzer", "TOOL_Coverity"]

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _load_problem_map() -> dict:
    if PROBLEM_MAP_PATH.exists():
        return json.loads(PROBLEM_MAP_PATH.read_text())
    return {}


def get_slugs() -> list[str]:
    dirs = sorted(EXPERIMENTS.glob("repository_*"))
    return [d.name.replace("repository_", "") for d in dirs if d.is_dir()]


def _slug_label(slug: str, problem_map: dict) -> str:
    name = problem_map.get(slug, "")
    return f"{slug} — {name}" if name else slug


def get_available_attacks(slug: str) -> list[str]:
    exp_dir = EXPERIMENTS / f"repository_{slug}"
    available = []
    for at in ATTACK_TYPES:
        if (exp_dir / f"solution_{at}.cpp").exists():
            available.append(at)
    return available


# ---------------------------------------------------------------------------
# Solution code
# ---------------------------------------------------------------------------

def load_solution(slug: str, at: str) -> str:
    path = EXPERIMENTS / f"repository_{slug}" / f"solution_{at}.cpp"
    return path.read_text() if path.exists() else "(solution file not found)"


# ---------------------------------------------------------------------------
# Trajectory
# ---------------------------------------------------------------------------

def _fmt_tool_output(content: str) -> str:
    rc_m = re.search(r"<returncode>(-?\d+)</returncode>", content)
    out_m = re.search(r"<output>(.*?)</output>", content, re.DOTALL)
    exc_m = re.search(r"<exception>(.*?)</exception>", content, re.DOTALL)
    rc  = rc_m.group(1) if rc_m else "?"
    out = out_m.group(1).strip() if out_m else ""
    exc = exc_m.group(1).strip() if exc_m else ""
    parts = [f"[exit {rc}]"]
    if exc:
        parts.append(f"exception: {exc}")
    if out:
        parts.append(out)
    return "\n".join(parts)


def format_trajectory(slug: str, at: str) -> str:
    path = EXPERIMENTS / f"repository_{slug}" / f"trajectory_{at}.json"
    if not path.exists():
        return "(trajectory file not found)"
    data = json.loads(path.read_text())
    msgs = data.get("messages", data.get("trajectory", []))
    lines = []
    step = 0
    for m in msgs:
        role = m.get("role", "")
        content = m.get("content") or ""
        tool_calls = m.get("tool_calls", [])
        extra = m.get("extra", {})

        if role == "system":
            lines.append("━━━ SYSTEM PROMPT (truncated) ━━━")
            lines.append(str(content)[:300] + " …\n")
        elif role == "user":
            lines.append("━━━ INSTANCE PROMPT (truncated) ━━━")
            lines.append(str(content)[:500] + " …\n")
        elif role == "assistant":
            step += 1
            if tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    name = fn.get("name", "?")
                    try:
                        args = json.loads(fn.get("arguments", "{}"))
                    except Exception:
                        args = fn.get("arguments", "")
                    cmd = args.get("command", args) if isinstance(args, dict) else args
                    lines.append(f"▶ Step {step}  [{name}]")
                    lines.append(f"  {str(cmd)[:400]}\n")
            else:
                lines.append(f"▶ Step {step}  [message]")
                lines.append(f"  {str(content)[:300]}\n")
        elif role == "tool":
            formatted = _fmt_tool_output(str(content))
            # Highlight key outcomes
            for keyword, marker in [
                ("CRASH_CONFIRMED", "✅ CRASH_CONFIRMED"),
                ("NO_CRASH",        "❌ NO_CRASH"),
                ("PASS",            "✅ PASS"),
                ("FAIL",            "❌ FAIL"),
                ("COMPILE_ERROR",   "⚠️  COMPILE_ERROR"),
                ("RUNTIME_ERROR",   "⚠️  RUNTIME_ERROR"),
                ("CANNOT_INJECT_NPD", "🚫 CANNOT_INJECT_NPD"),
            ]:
                if keyword in formatted:
                    formatted = formatted.replace(keyword, marker)
            lines.append(f"  → {formatted}\n")
        elif role == "exit":
            status = extra.get("exit_status", str(content)[:80])
            lines.append(f"━━━ EXIT: {status} ━━━\n")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# RepoAudit
# ---------------------------------------------------------------------------

def _latest_ra_run_dir(slug: str) -> Path | None:
    candidates = sorted((RA_RESULTS / slug).glob("*/"), key=lambda p: p.name)
    return candidates[-1] if candidates else None


def _detect_info(slug: str) -> dict:
    run_dir = _latest_ra_run_dir(slug)
    if not run_dir:
        return {}
    p = run_dir / "detect_info.json"
    return json.loads(p.read_text()) if p.exists() else {}


def ra_verdict(slug: str, at: str) -> str:
    data = _detect_info(slug)
    fname = f"{slug}_{at}.cpp"
    for v in data.values():
        bv = v.get("buggy_value", "")
        if fname in bv:
            return "DETECTED"
    # Check if any result file exists at all
    run_dir = _latest_ra_run_dir(slug)
    if run_dir and (run_dir / "detect_info.json").exists():
        return "EVADED"
    return "N/A"


def load_ra_log(slug: str, at: str) -> str:
    # Logs live under RA_LOGS/slug/<run_id>/slug_AT.log
    log_dirs = sorted((RA_LOGS / slug).glob("*/"), key=lambda p: p.name)
    if not log_dirs:
        return "(no RepoAudit log found)"
    log_dir = log_dirs[-1]
    log_file = log_dir / f"{slug}_{at}.log"
    if not log_file.exists():
        return f"(log file not found: {log_file.name})"
    return log_file.read_text()


def format_ra_log(log_text: str) -> str:
    lines = []
    # Explorer sections
    parts = re.split(r"\[EXPLORER\] Analyzing ", log_text)
    explorer_sections = []
    for part in parts[1:]:
        m = re.match(r"(.+?)\(\) for source '(.+?)' .* at line (\d+)", part)
        func = m.group(1).strip() if m else "?"
        src  = m.group(2).strip() if m else "?"
        line = m.group(3).strip() if m else "?"
        resp_m = re.search(r"Response:\s*\n(.+?)(?=\n\d{4}-|\Z)", part, re.DOTALL)
        response = resp_m.group(1).strip() if resp_m else ""
        out_m = re.search(r"\[EXPLORER\] Output: (.+)", part)
        output = out_m.group(1).strip() if out_m else "?"
        explorer_sections.append({"func": func, "src": src, "line": line,
                                   "response": response, "output": output})

    lines.append("▶▶▶ EXPLORER ◀◀◀\n")
    if not explorer_sections:
        lines.append("(no IntraDataFlowAnalyzer calls found)\n")
    for i, s in enumerate(explorer_sections, 1):
        lines.append(f"── Explorer call {i}: {s['func']}()  src='{s['src']}' @ line {s['line']} ──")
        lines.append(s["response"])
        lines.append(f"\n  → Output: {s['output']}\n")

    # Validator sections
    val_parts = re.split(r"The LLM Tool PathValidator is invoked\.", log_text)
    lines.append("▶▶▶ VALIDATOR ◀◀◀\n")
    if len(val_parts) <= 1:
        lines.append("(no PathValidator calls — Explorer found no propagation paths)\n")
    for i, part in enumerate(val_parts[1:], 1):
        path_lines = re.findall(r" - \(.*?\) in the function .+? at the line \d+", part)
        path_desc = "\n".join(path_lines) or "(path not extracted)"
        resp_m = re.search(r"Response:\s*\n(.+?)(?=\n\d{4}-|\Z)", part, re.DOTALL)
        response = resp_m.group(1).strip() if resp_m else ""
        ans_m = re.search(r"Answer:\s*(Yes|No)", response)
        answer = ans_m.group(1) if ans_m else "?"
        label = "✅ Yes (bug confirmed)" if answer == "Yes" else "✗ No (path dismissed)"
        lines.append(f"── Validator call {i}: {label} ──")
        lines.append("Propagation path:\n" + path_desc)
        lines.append("\n" + response + "\n")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# VulnLLM-R
# ---------------------------------------------------------------------------

def _vl_result_file(slug: str) -> Path | None:
    candidates = sorted((VL_RESULTS / slug).glob("*.json"))
    return candidates[-1] if candidates else None


def _vl_idx_map(slug: str) -> dict:
    """Map idx → attack_type from dataset files."""
    idx_map = {}
    ds_dir = VL_DATASETS / slug / "c"
    if not ds_dir.exists():
        return idx_map
    for fname in ds_dir.glob("*.json"):
        try:
            entries = json.loads(fname.read_text())
            for e in entries:
                idx_map[e["idx"]] = e["attack_type"]
        except Exception:
            pass
    return idx_map


def vl_verdict(slug: str, at: str) -> str:
    rf = _vl_result_file(slug)
    if not rf:
        return "N/A"
    data = json.loads(rf.read_text())
    idx_map = _vl_idx_map(slug)
    for item in data[1:]:  # data[0] is summary
        if idx_map.get(item.get("idx")) == at:
            pred = item.get("predicted_is_vulnerable", "")
            return "DETECTED" if pred == "yes" else "EVADED"
    return "N/A"


def load_vl_output(slug: str, at: str) -> str:
    rf = _vl_result_file(slug)
    if not rf:
        return "(no VulnLLM-R result file found)"
    data = json.loads(rf.read_text())
    idx_map = _vl_idx_map(slug)
    for item in data[1:]:
        if idx_map.get(item.get("idx")) == at:
            pred  = item.get("predicted_is_vulnerable", "?")
            cwe   = item.get("predicted_vulnerability_type", "N/A")
            out   = item.get("output", "")
            return f"predicted_is_vulnerable: {pred}  |  predicted_cwe: {cwe}\n{'─'*60}\n{out}"
    return f"(no entry found for attack_type={at} — may not be in dataset)"


# ---------------------------------------------------------------------------
# Trajectory quality flags
# ---------------------------------------------------------------------------

def _traj_flags(slug: str, at: str) -> tuple[bool, bool]:
    """Return (submit_pass, crash_confirmed) by scanning trajectory tool results."""
    path = EXPERIMENTS / f"repository_{slug}" / f"trajectory_{at}.json"
    if not path.exists():
        return False, False
    data = json.loads(path.read_text())
    msgs = data.get("messages", data.get("trajectory", []))
    submit_pass = False
    crash_confirmed = False
    for m in msgs:
        if m.get("role") != "tool":
            continue
        c = str(m.get("content", ""))
        out_m = re.search(r"<output>(.*?)</output>", c, re.DOTALL)
        if out_m and "PASS" in out_m.group(1) and "FAIL" not in out_m.group(1):
            submit_pass = True
        if "CRASH_CONFIRMED" in c:
            crash_confirmed = True
    return submit_pass, crash_confirmed


# ---------------------------------------------------------------------------
# Verdict badge HTML
# ---------------------------------------------------------------------------

def _badge(label: str, status: str) -> str:
    colors = {
        "DETECTED": ("background:#d4edda;color:#155724", "✓"),
        "EVADED":   ("background:#f8d7da;color:#721c24", "✗"),
        "N/A":      ("background:#e2e3e5;color:#383d41", "—"),
    }
    style, icon = colors.get(status, colors["N/A"])
    return (f'<span style="{style};padding:3px 12px;border-radius:4px;'
            f'font-weight:bold;font-size:1em">{icon} {label}: {status}</span>')


def _flag_badge(label: str, ok: bool) -> str:
    style = "background:#d4edda;color:#155724" if ok else "background:#f8d7da;color:#721c24"
    icon  = "✓" if ok else "✗"
    return (f'<span style="{style};padding:3px 10px;border-radius:4px;'
            f'font-size:0.9em">{icon} {label}</span>')


def make_verdicts_html(slug: str, at: str) -> str:
    ra = ra_verdict(slug, at)
    vl = vl_verdict(slug, at)
    sp, cc = _traj_flags(slug, at)
    badges = " &nbsp; ".join([
        _badge("RepoAudit", ra),
        _badge("VulnLLM-R", vl),
        _flag_badge("submit PASS", sp),
        _flag_badge("CRASH_CONFIRMED", cc),
    ])
    return f'<div style="display:flex;gap:8px;align-items:center;padding:8px 0;flex-wrap:wrap">{badges}</div>'


# ---------------------------------------------------------------------------
# Load everything for a given (slug, attack)
# ---------------------------------------------------------------------------

def load_all(slug_label: str, at: str, slug_map: dict):
    slug = slug_map.get(slug_label, slug_label)
    verdicts   = make_verdicts_html(slug, at)
    solution   = load_solution(slug, at)
    trajectory = format_trajectory(slug, at)
    ra_raw     = load_ra_log(slug, at)
    ra_fmt     = format_ra_log(ra_raw)
    vl_out     = load_vl_output(slug, at)
    return verdicts, solution, trajectory, ra_fmt, vl_out


# ---------------------------------------------------------------------------
# Build UI
# ---------------------------------------------------------------------------

problem_map   = _load_problem_map()
slugs         = get_slugs()
slug_labels   = [_slug_label(s, problem_map) for s in slugs]
slug_map      = {_slug_label(s, problem_map): s for s in slugs}

init_slug_label = slug_labels[0] if slug_labels else ""
init_slug       = slugs[0] if slugs else ""
init_attacks    = get_available_attacks(init_slug)
init_at         = init_attacks[0] if init_attacks else ""

init_verdicts, init_sol, init_traj, init_ra, init_vl = (
    load_all(init_slug_label, init_at, slug_map) if init_at else ("", "", "", "", "")
)


def on_problem_change(slug_label: str):
    slug    = slug_map.get(slug_label, "")
    attacks = get_available_attacks(slug)
    at      = attacks[0] if attacks else ""
    v, sol, traj, ra, vl = load_all(slug_label, at, slug_map) if at else ("", "", "", "", "")
    return gr.update(choices=attacks, value=at), v, sol, traj, ra, vl


def on_attack_change(slug_label: str, at: str):
    return load_all(slug_label, at, slug_map)


with gr.Blocks(title="Attacker Viewer", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# Attacker Pipeline Viewer")
    gr.Markdown("Browse agent-generated solutions, trajectories, and auditor outputs.")

    with gr.Row():
        problem_dd = gr.Dropdown(
            choices=slug_labels, value=init_slug_label,
            label="Problem", scale=3,
        )
        attack_dd = gr.Dropdown(
            choices=init_attacks, value=init_at,
            label="Attack type", scale=1,
        )

    verdict_html = gr.HTML(value=init_verdicts)

    with gr.Tabs():
        with gr.Tab("Solution Code"):
            sol_box = gr.Code(value=init_sol, language="cpp", label="", lines=40)

        with gr.Tab("Agent Trajectory"):
            traj_box = gr.Textbox(
                value=init_traj, label="",
                lines=40, max_lines=80,
                show_copy_button=True,
            )

        with gr.Tab("RepoAudit"):
            ra_box = gr.Textbox(
                value=init_ra, label="",
                lines=40, max_lines=80,
                show_copy_button=True,
            )

        with gr.Tab("VulnLLM-R"):
            vl_box = gr.Textbox(
                value=init_vl, label="",
                lines=40, max_lines=80,
                show_copy_button=True,
            )

    all_outputs = [verdict_html, sol_box, traj_box, ra_box, vl_box]

    problem_dd.change(
        on_problem_change,
        inputs=[problem_dd],
        outputs=[attack_dd] + all_outputs,
    )
    attack_dd.change(
        on_attack_change,
        inputs=[problem_dd, attack_dd],
        outputs=all_outputs,
    )


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=7860)
    args, _ = p.parse_known_args()
    demo.launch(server_name="0.0.0.0", server_port=args.port, share=False)
