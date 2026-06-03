#!/usr/bin/env python3
"""
Viewer for CVE-mined NPD benchmark samples (samples_cve/).

Shows per-sample: context.cc, starter.cc, stub diff, task.md, tests.cc, metadata.

Usage:
    python viewer_samples_cve.py [--port 8083] [--samples-dir samples_cve]
"""

import argparse
import difflib
import json
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

HERE        = Path(__file__).parent
DEFAULT_DIR = HERE / "samples_cve"


def _make_diff(a_text: str, b_text: str) -> list[dict]:
    a = (a_text or "").splitlines()
    b = (b_text or "").splitlines()
    out = []
    for group in difflib.SequenceMatcher(None, a, b).get_grouped_opcodes(3):
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for line in a[i1:i2]:
                    out.append({"t": "ctx", "line": line})
            if tag in ("replace", "delete"):
                for line in a[i1:i2]:
                    out.append({"t": "del", "line": line})
            if tag in ("replace", "insert"):
                for line in b[j1:j2]:
                    out.append({"t": "add", "line": line})
    return out


def load_sample(d: Path) -> dict:
    meta_path = d / "metadata.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    buggy   = (d / "context.cc"  ).read_text() if (d / "context.cc"  ).exists() else ""
    starter = (d / "starter.cc").read_text() if (d / "starter.cc").exists() else ""
    task_md = (d / "task.md"   ).read_text() if (d / "task.md"   ).exists() else ""
    tests   = (d / "tests.cc"  ).read_text() if (d / "tests.cc"  ).exists() else ""

    diff = _make_diff(starter, buggy)

    return {
        "id":        d.name,
        "meta":      meta,
        "context":     buggy,
        "starter":   starter,
        "task_md":   task_md,
        "tests":     tests,
        "diff":      diff,
        "has_task":  bool(task_md),
        "has_tests": bool(tests),
    }


def build_app(samples_dir: Path) -> FastAPI:
    app = FastAPI(title="CVE Samples Viewer")

    samples: dict[str, dict] = {}
    for d in sorted(samples_dir.iterdir()):
        if d.is_dir() and (d / "metadata.json").exists():
            try:
                samples[d.name] = load_sample(d)
            except Exception as e:
                print(f"WARN: skipping {d.name}: {e}")

    @app.get("/api/samples")
    def list_samples():
        return [
            {
                "id":            s["id"],
                "cve_id":        s["meta"].get("cve_id", ""),
                "function":      s["meta"].get("function", ""),
                "lang":          s["meta"].get("lang", "c"),
                "file":          s["meta"].get("file", ""),
                "repo_url":      s["meta"].get("repo_url", ""),
                "has_task":      s["has_task"],
                "has_tests":     s["has_tests"],
                "has_diff":      bool(s["diff"]),
            }
            for s in samples.values()
        ]

    @app.get("/api/sample")
    def get_sample(id: str = Query(...)):
        if id not in samples:
            raise HTTPException(404, f"{id!r} not found")
        return samples[id]

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTML

    return app


HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<title>CVE Samples Viewer</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/cpp.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/c.min.js"></script>
<link rel="stylesheet" id="hljs-theme"
  href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#30363d;
  --border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;
  --sidebar:300px;--mono:'SF Mono','Fira Code',Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --radius:6px;
}
[data-theme=light]{
  --bg:#fff;--bg2:#f6f8fa;--bg3:#eaeef2;--bg4:#d0d7de;
  --border:#d0d7de;--text:#1f2328;--text2:#656d76;--text3:#8c959f;
  --accent:#0969da;--green:#1a7f37;--red:#d1242f;--yellow:#9a6700;
}
html,body{height:100%;font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px}
#app{display:flex;height:100vh;overflow:hidden}

/* sidebar */
#sidebar{width:var(--sidebar);min-width:var(--sidebar);background:var(--bg2);
  border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.sb-head{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.sb-title{font-weight:700;font-size:13px;flex:1}
.sb-title span{color:var(--accent)}
.icon-btn{background:none;border:1px solid var(--border);border-radius:var(--radius);
  color:var(--text2);padding:4px 8px;cursor:pointer;font-size:12px}
.icon-btn:hover{background:var(--bg3);color:var(--text)}
#sample-list{flex:1;overflow-y:auto;padding:4px 0}
.s-item{padding:9px 14px;cursor:pointer;border-left:3px solid transparent;transition:background .12s}
.s-item:hover{background:var(--bg3)}
.s-item.active{background:var(--bg3);border-left-color:var(--accent)}
.s-cve{font-weight:700;font-size:12px;font-family:var(--mono);color:var(--accent)}
.s-fn{font-size:12px;font-family:var(--mono);color:var(--text)}
.s-file{font-size:11px;color:var(--text3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.s-badges{display:flex;gap:4px;margin-top:3px}
.badge{font-size:10px;font-weight:600;padding:1px 5px;border-radius:3px}
.badge-ok{background:color-mix(in srgb,var(--green) 18%,transparent);color:var(--green)}
.badge-warn{background:color-mix(in srgb,var(--yellow) 18%,transparent);color:var(--yellow)}
.badge-lang{background:color-mix(in srgb,var(--accent) 15%,transparent);color:var(--accent)}

/* main */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#empty{display:flex;align-items:center;justify-content:center;height:100%;
  flex-direction:column;gap:8px;color:var(--text3)}
#detail{display:none;flex-direction:column;height:100%;overflow:hidden}
#hdr{padding:12px 20px;border-bottom:1px solid var(--border);background:var(--bg2);
  display:flex;align-items:flex-start;gap:12px;flex-shrink:0}
#hdr-left{flex:1;min-width:0}
#hdr-cve{font-size:17px;font-weight:700;font-family:var(--mono);color:var(--accent)}
#hdr-fn{font-size:13px;font-family:var(--mono);color:var(--text);margin-top:2px}
#hdr-file{font-size:11px;color:var(--text3);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#hdr-links{display:flex;gap:8px;flex-shrink:0}
#tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg2);
  padding:0 16px;flex-shrink:0}
.tab{padding:10px 14px;font-size:13px;cursor:pointer;color:var(--text2);
  border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .12s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab.missing{opacity:.4}
#content{flex:1;overflow-y:auto;padding:20px}

/* code */
.code-wrap{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;font-family:var(--mono);font-size:12.5px;line-height:1.6}
.code-line{display:flex}
.line-num{user-select:none;color:var(--text3);text-align:right;padding:0 12px;
  min-width:50px;background:var(--bg3);border-right:1px solid var(--border);flex:none}
.line-src{padding:0 12px;white-space:pre;flex:1;overflow-x:auto}

/* diff */
.diff-wrap{font-family:var(--mono);font-size:12.5px;line-height:1.6;
  border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.diff-line{display:flex;padding:0 12px}
.diff-line.add{background:color-mix(in srgb,var(--green) 12%,transparent);color:var(--green)}
.diff-line.del{background:color-mix(in srgb,var(--red) 12%,transparent);color:var(--red)}
.diff-line.ctx{color:var(--text2)}
.diff-tag{min-width:18px;flex:none;user-select:none;font-weight:700}
.diff-src{white-space:pre;flex:1}
.diff-sep{padding:4px 12px;color:var(--text3);font-size:11px;
  background:var(--bg3);border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.no-diff{color:var(--yellow);padding:16px;font-size:13px;
  background:color-mix(in srgb,var(--yellow) 8%,transparent);
  border:1px dashed color-mix(in srgb,var(--yellow) 40%,transparent);
  border-radius:var(--radius)}

/* markdown */
.md-body{font-size:13px;line-height:1.75;color:var(--text)}
.md-body h1{font-size:18px;margin:0 0 12px;color:var(--accent)}
.md-body h2{font-size:14px;font-weight:700;margin:20px 0 8px;color:var(--text)}
.md-body p{margin:0 0 10px}
.md-body ul,.md-body ol{margin:0 0 10px 20px}
.md-body code{font-family:var(--mono);font-size:12px;background:var(--bg3);
  padding:1px 5px;border-radius:3px}
.md-body pre{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:12px;overflow-x:auto;margin:0 0 12px}
.md-body pre code{background:none;padding:0}

/* meta */
.meta-grid{display:grid;grid-template-columns:140px 1fr;gap:1px;
  background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.mk{background:var(--bg2);padding:7px 12px;font-size:12px;color:var(--text2);font-weight:600}
.mv{background:var(--bg);padding:7px 12px;font-size:12px;font-family:var(--mono);word-break:break-all}
.mv a{color:var(--accent)}
.section-label{font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.06em;color:var(--text3);margin:16px 0 8px}
.section-label:first-child{margin-top:0}
</style>
</head>
<body>
<div id="app">
  <div id="sidebar">
    <div class="sb-head">
      <div class="sb-title">CVE <span>Samples</span></div>
      <button class="icon-btn" onclick="toggleTheme()">☀/☾</button>
    </div>
    <div id="sample-list"></div>
  </div>
  <div id="main">
    <div id="empty"><div style="font-size:40px">🔬</div><div>Select a sample</div></div>
    <div id="detail">
      <div id="hdr">
        <div id="hdr-left">
          <div id="hdr-cve"></div>
          <div id="hdr-fn"></div>
          <div id="hdr-file"></div>
        </div>
        <div id="hdr-links"></div>
      </div>
      <div id="tabs">
        <div class="tab active" data-tab="context">context.cc</div>
        <div class="tab" data-tab="starter">starter.cc</div>
        <div class="tab" data-tab="diff">Stub diff</div>
        <div class="tab" data-tab="task">task.md</div>
        <div class="tab" data-tab="tests">tests.cc</div>
        <div class="tab" data-tab="meta">Metadata</div>
      </div>
      <div id="content"></div>
    </div>
  </div>
</div>
<script>
let all = [], current = null, currentTab = 'diff';

function toggleTheme() {
  const h = document.documentElement;
  const next = h.dataset.theme === 'dark' ? 'light' : 'dark';
  h.dataset.theme = next;
  document.getElementById('hljs-theme').href = next === 'dark'
    ? 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css'
    : 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css';
}
function esc(s) {
  return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function init() {
  all = await fetch('/api/samples').then(r => r.json());
  const list = document.getElementById('sample-list');
  list.innerHTML = '';
  for (const s of all) {
    const el = document.createElement('div');
    el.className = 's-item'; el.dataset.id = s.id;
    const repo = (s.repo_url||'').replace('https://github.com/','');
    const diffBadge = '';
    const taskBadge = s.has_task  ? '<span class="badge badge-ok">task</span>'  : '';
    const testBadge = s.has_tests ? '<span class="badge badge-ok">tests</span>' : '';
    const langBadge = `<span class="badge badge-lang">${esc(s.lang)}</span>`;
    el.innerHTML = `
      <div class="s-cve">${esc(s.cve_id)}</div>
      <div class="s-fn">${esc(s.function)}</div>
      <div class="s-file">${esc(repo)}</div>
      <div class="s-badges">${langBadge}${diffBadge}${taskBadge}${testBadge}</div>`;
    el.addEventListener('click', () => select(s.id));
    list.appendChild(el);
  }
}

async function select(id) {
  document.querySelectorAll('.s-item').forEach(e =>
    e.classList.toggle('active', e.dataset.id === id));
  const s = await fetch(`/api/sample?id=${encodeURIComponent(id)}`).then(r => r.json());
  current = s;

  document.getElementById('empty').style.display = 'none';
  const det = document.getElementById('detail');
  det.style.display = 'flex'; det.style.flexDirection = 'column';
  det.style.height = '100%'; det.style.overflow = 'hidden';

  const m = s.meta;
  document.getElementById('hdr-cve').textContent = m.cve_id || s.id;
  document.getElementById('hdr-fn').textContent  = m.function || '';
  document.getElementById('hdr-file').textContent =
    `${m.file || ''}  ·  ${(m.repo_url||'').replace('https://github.com/','')}`;

  const links = document.getElementById('hdr-links');
  links.innerHTML = '';
  if (m.nvd_url) {
    const a = document.createElement('a');
    a.href = m.nvd_url; a.target = '_blank'; a.className = 'icon-btn'; a.textContent = 'NVD ↗';
    links.appendChild(a);
  }
  if (m.commit_url) {
    const a = document.createElement('a');
    a.href = m.commit_url; a.target = '_blank'; a.className = 'icon-btn'; a.textContent = 'Commit ↗';
    links.appendChild(a);
  }

  // Update tab availability
  document.querySelector('[data-tab=task ]').classList.toggle('missing', !s.has_task);
  document.querySelector('[data-tab=tests]').classList.toggle('missing', !s.has_tests);

  showTab(currentTab);
}

document.querySelectorAll('.tab').forEach(t =>
  t.addEventListener('click', () => showTab(t.dataset.tab)));

function showTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === tab));
  if (!current) return;
  const c = document.getElementById('content');
  c.innerHTML = '';
  if      (tab === 'diff')    renderDiff(c);
  else if (tab === 'buggy')   renderCode(c, current.buggy,   current.meta.lang);
  else if (tab === 'starter') renderCode(c, current.starter, current.meta.lang);
  else if (tab === 'task')      renderTask(c);
  else if (tab === 'tests')     renderCode(c, current.tests,     current.meta.lang);
  else if (tab === 'meta')      renderMeta(c);
}

function renderCode(container, src, lang) {
  if (!src) { container.innerHTML = '<div style="color:var(--text3);padding:20px">Not available.</div>'; return; }
  const hlLang = lang === 'cpp' ? 'cpp' : 'c';
  const highlighted = hljs.highlight(src, {language: hlLang}).value;
  const lines = highlighted.split('\n');
  const wrap = document.createElement('div'); wrap.className = 'code-wrap';
  lines.forEach((lineHtml, i) => {
    const row = document.createElement('div'); row.className = 'code-line';
    const num = document.createElement('span'); num.className = 'line-num'; num.textContent = i + 1;
    const src = document.createElement('span'); src.className = 'line-src'; src.innerHTML = lineHtml || ' ';
    row.appendChild(num); row.appendChild(src); wrap.appendChild(row);
  });
  container.appendChild(wrap);
}

function renderDiff(container) {
  const diff = current.diff || [];
  if (!diff.length) {
    const box = document.createElement('div'); box.className = 'no-diff';
    box.textContent = 'No diff — starter.cc and context.cc are identical (stub replacement may have failed).';
    container.appendChild(box);
    return;
  }
  const added   = diff.filter(d => d.t === 'add').length;
  const removed = diff.filter(d => d.t === 'del').length;
  const hdr = document.createElement('div');
  hdr.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:10px;font-size:12px;';
  hdr.innerHTML = `<strong style="color:var(--text2)">starter.cc → context.cc</strong>
    <span style="color:var(--green)">+${added}</span>
    <span style="color:var(--red)">-${removed}</span>
    <span style="color:var(--text3);font-size:11px">additions = what the model needs to implement</span>`;
  container.appendChild(hdr);

  const wrap = document.createElement('div'); wrap.className = 'diff-wrap';
  diff.forEach((entry, i) => {
    const prev = diff[i - 1];
    if (i > 0 && entry.t === 'ctx' && prev && prev.t !== 'ctx') {
      const sep = document.createElement('div'); sep.className = 'diff-sep';
      sep.textContent = '···'; wrap.appendChild(sep);
    }
    const row = document.createElement('div');
    row.className = `diff-line ${entry.t === 'add' ? 'add' : entry.t === 'del' ? 'del' : 'ctx'}`;
    const tag = document.createElement('span'); tag.className = 'diff-tag';
    tag.textContent = entry.t === 'add' ? '+' : entry.t === 'del' ? '-' : ' ';
    const src = document.createElement('span'); src.className = 'diff-src';
    src.textContent = entry.line;
    row.appendChild(tag); row.appendChild(src); wrap.appendChild(row);
  });
  container.appendChild(wrap);
}

function renderTask(container) {
  if (!current.task_md) {
    container.innerHTML = '<div style="color:var(--text3);padding:20px">task.md not generated yet — run generate_task_cve.py.</div>';
    return;
  }
  // Very minimal markdown render: headings, code fences, paragraphs
  let html = current.task_md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
    .replace(/```[a-z]*\n([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^(?!<[h|p|u|o|l|p])/gm, '');
  const div = document.createElement('div'); div.className = 'md-body';
  div.innerHTML = '<p>' + html + '</p>';
  container.appendChild(div);
}

function renderMeta(container) {
  const m = current.meta;
  const grid = document.createElement('div'); grid.className = 'meta-grid';
  const rows = [
    ['Pilot ID',   esc(m.pilot_id || '')],
    ['CVE',        m.nvd_url ? `<a href="${esc(m.nvd_url)}" target="_blank">${esc(m.cve_id)}</a>` : esc(m.cve_id || '')],
    ['Function',   esc(m.function || '')],
    ['File',       esc(m.file || '')],
    ['Language',   esc(m.lang || '')],
    ['Repo',       m.repo_url ? `<a href="${esc(m.repo_url)}" target="_blank">${esc(m.repo_url)}</a>` : '—'],
    ['Fix commit', m.commit_url ? `<a href="${esc(m.commit_url)}" target="_blank">${esc((m.commit_hash||'').slice(0,12))}…</a>` : esc(m.commit_hash || '—')],
    ['Diff ptrs',  esc((m.diff_ptrs||[]).join(', ') || '—')],
    ['Source',     esc(m.source || '')],
  ];
  for (const [k, v] of rows) {
    const key = document.createElement('div'); key.className = 'mk'; key.textContent = k;
    const val = document.createElement('div'); val.className = 'mv'; val.innerHTML = v;
    grid.appendChild(key); grid.appendChild(val);
  }
  container.appendChild(grid);
}

init();
</script>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8083)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--samples-dir", default=str(DEFAULT_DIR))
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    if not samples_dir.exists():
        print(f"ERROR: {samples_dir} not found", file=sys.stderr)
        sys.exit(1)

    app = build_app(samples_dir)
    print(f"Viewer at http://localhost:{args.port}  ({samples_dir})")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
