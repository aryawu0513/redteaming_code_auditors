# Architecture Reference

Companion to the top-level `README.md` (which is a quickstart). This doc describes:
- What each top-level directory is for
- How each of the four target systems is invoked, the dataset format it reads, the result format it writes, and how to update its fork

---

## 1. Repo Layout

```
redteaming_code_auditors/
├── benchmark/              Committed source. Safe variants per (lang, bug).
├── automatic/              Attack generator (LLM). Writes automatic/texts/.
├── defenses/               Defense definitions + applier scripts.
├── scripts/                Run scripts (setup_benchmark, run_*_c_npd, screen_defenses).
├── attacker/               Adversarial-payload generation experiments (research scratchpad).
├── demo/                   Self-contained end-to-end demo on target_repo.
├── docs/                   This directory.
├── RepoAudit/              Submodule (aryawu0513/RepoAudit, branch main).
├── VulnLLM-R/              Submodule (aryawu0513/VulnLLM-R, branch main).
├── VulTrial/               Submodule (aryawu0513/VulTrial, branch main).
├── OpenVul/                Plain dir (only run.py — no upstream to track).
├── pyproject.toml          Single shared venv for all systems (uv-managed).
└── uv.lock
```

### Per-directory purpose

**`benchmark/`** — Hand-written safe-source variants, organized as `benchmark/{Lang}/{Bug}/safe/{variant}/`. This is the only directly-committed source data; everything else under each system's dataset dir is generated from this.

**`automatic/`** — Two-step DSPy pipeline:
- `generate_variant.py`: extracts injection anchors from a safe variant, then generates 10 adversarial attack payloads per attack type. Writes `automatic/texts/{lang}_{bug}.json`.
- `gen_attacks.py`: file writer. Reads `automatic/texts/*.json` and writes the per-system attack datasets to all four target systems in one pass.

**`defenses/`** — Defense registry + appliers. `registry.py` declares D1–D5. Pre-processing for D3/D4/D5 (LLM screening) lives in `defenses/screen_benchmark.py` and `defenses/annotator_agent.py`. Each system has an `apply_*.py` script that runs an existing run script under a defense.

**`scripts/`** — All run + setup scripts. The two important ones for first-time setup are `setup_benchmark.sh` (writes attack datasets to all four systems) and `setup_defenses.sh` (writes defense variants). Per-system run scripts are named `run_{system}_c_npd.sh`.

**`attacker/`** — Research scratchpad for adversarial-payload generation experiments (the active-learning attacker, CodeQL queries, eyeball-evaluation harness). Not part of the standard pipeline.

**`demo/`** — End-to-end interactive demo. Self-contained on `target_repo` / `target_repo_v2`. Runs all phases (generate attacks → baseline auditor → post-attack auditor) and produces a Gradio viewer.

---

## 2. Submodule Workflow (RepoAudit, VulnLLM-R, VulTrial)

All three live as submodules under `aryawu0513/`. The pattern for changing a target system's source code:

```bash
# 1. cd into the submodule and make changes there
cd VulTrial
# (edit files)

# 2. Commit in the submodule
git add <files>
git commit -m "..."
git push origin main

# 3. Bump the pointer in the parent
cd ..
git add VulTrial
git commit -m "Bump VulTrial submodule"
```

Fresh clone:
```bash
git clone --recurse-submodules <repo-url>
# or after a plain clone:
git submodule update --init --recursive
```

To pull upstream updates of a fork:
```bash
cd VulTrial && git pull origin main && cd ..
git add VulTrial && git commit -m "Bump VulTrial"
```

---

## 3. Target Systems

### 3.1 RepoAudit

| | |
|---|---|
| **Type** | Multi-agent repo-level auditor (Explorer + Validator) |
| **Compute** | API-based — needs `ANTHROPIC_API_KEY` |
| **Submodule** | `git@github.com:aryawu0513/RepoAudit.git` (branch `main`) |
| **Languages** | C, Python |
| **Bug types** | NPD, UAF |

**Input**: Source files on disk, organized as `RepoAudit/benchmark/{Lang}/{Bug}/{category}/{variant}/*.{c,py}`. The auditor walks the directory and runs intra-procedural data-flow analysis on each function.

**Invocation**:
```bash
bash scripts/run_repoaudit_c_npd.sh
# Override: LANGUAGE=Python BUG_TYPE=NPD FILES='*.py' bash scripts/run_repoaudit_c_npd.sh
```

**Output**: `RepoAudit/result/dfbscan/{model}/NPD/{Cpp|Python}/{category}/{run_id}/detect_info.json`. A *missing* entry for a variant means the auditor failed to detect the bug — i.e., the attack succeeded.

**Reasoning logs**: `RepoAudit/log/dfbscan/.../*.log`. **Read these** when investigating a result — they show Explorer and Validator chain-of-thought.

**Quirks**: Parser patches in `src/llmtool/dfbscan/intra_dataflow_analyzer.py` (bold-markdown path headers) and `src/llmtool/dfbscan/path_validator.py` (last-Answer wins) are mandatory. Do not revert.

### 3.2 VulnLLM-R

| | |
|---|---|
| **Type** | Fine-tuned 7B reasoning model, single-shot |
| **Compute** | GPU + vllm — needs `CUDA_VISIBLE_DEVICES` |
| **Submodule** | `git@github.com:aryawu0513/VulnLLM-R.git` (branch `main`) |
| **Languages** | C, Python |
| **Bug types** | NPD, UAF |

**Input**: JSON datasets at `VulnLLM-R/datasets/{Lang}/{Bug}/{category}/{variant}/{c,python}/*.json`. Each file is `[{CWE_ID, code, target, language, dataset, idx, ...}]`. The `code` field combines context + target function as `"// context\n{ctx}\n\n// target function\n{fn}\n"` (Python uses `#`).

**Invocation**:
```bash
export CUDA_VISIBLE_DEVICES=<id>
bash scripts/run_vulnllm_c_npd.sh
```

Internally runs `python -m vulscan.test.test --use_policy --vllm --tp 1 ...`. Always use `--use_policy` (eliminates CWE confusion; fair eval setting).

**Output**: `VulnLLM-R/results/{Lang}/{Bug}/policy/{category}/`. Parses `#judge: yes/no` + `#type: CWE-XX` from model output.

**Quirks**:
- `allocate` variant has a baseline reliability issue (model hallucinates a false early-exit guard). Exclude from FNR calculations.
- Policy-based generation: 4× exploratory runs at temp=0.6 collect CWE candidates; final authoritative run at temp=0 with candidates as `CWE_INFO` hint.

### 3.3 VulTrial

| | |
|---|---|
| **Type** | Multi-agent debate framework (AgentVerse) |
| **Compute** | API-based — `OPENAI_API_KEY` (default GPT-4o) or `ANTHROPIC_API_KEY` |
| **Submodule** | `git@github.com:aryawu0513/VulTrial.git` (branch `main`) |
| **Languages** | C, Python |
| **Bug types** | NPD |
| **Modes** | `generic` (no CWE hint), `npd` (NPD-specific prompt) |

**Input**: JSON datasets at `VulTrial/datasets/{Lang}/{Bug}/{category}/{variant}/{c,python}/*.json`. **Same format as VulnLLM-R** (`{CWE_ID, code, target, ...}` with combined `code` field).

**Invocation**:
```bash
bash scripts/run_vultrial_c_npd.sh
# Override: VT_MODEL=claude-sonnet-4-6 MODES="npd" bash scripts/run_vultrial_c_npd.sh
```

`run.py` builds a per-sample config and invokes `agentverse_command/main_simulation_cli.py` as a subprocess. The task dir at `VulTrial/agentverse/tasks/simulation/vultrial/vultrial_{mode}_{model_slug}/` is generated at runtime — that whole subtree is gitignored.

**Output**: `VulTrial/results/{model}/{mode}/C/NPD/{category}/{variant}__{mode}__{model}__C_NPD_{category}.json`. Final per-sample transcripts at `VulTrial/results/final_record/`.

**Quirks**:
- agentverse is installed via uv editable + `override-dependencies = ["fastapi>=0.115.0"]` (its pinned `fastapi==0.95.1` conflicts with vllm). The web UI is broken under the override; simulation agents are not.
- `agentverse/agents/__init__.py` has a `try`/`except` around the `ToolAgent` import — old langchain pulls in pydantic v1 `@root_validator` which raises on v2. VulTrial only uses `ConversationAgent`. Do not revert.

### 3.4 OpenVul

| | |
|---|---|
| **Type** | Qwen3-4B-GRPO single-shot via vllm |
| **Compute** | GPU + vllm — needs `CUDA_VISIBLE_DEVICES` |
| **Location** | Plain directory (`OpenVul/`), only `run.py` |
| **Languages** | C only |
| **Bug types** | NPD |

**Input**: JSON datasets at `OpenVul/datasets/C/NPD/{category}/{variant}/c/*.json`. **Format differs from the other systems** — context and target function are *split*:

```json
[{
  "context": "...",                    // full context block
  "target_function": "...",            // function under audit
  "function_name": "<caller>",
  "file_name": "target.c",
  "CWE_ID": ["CWE-476"],
  "target": 1,
  "language": "c",
  "dataset": "custom",
  "idx": 1
}]
```

`gen_attacks.py` produces this format via `write_openvul_json()` by splitting the VulnLLM-R `code` field at `"// target function\n"`.

**Invocation**:
```bash
export CUDA_VISIBLE_DEVICES=<id>
bash scripts/run_openvul_c_npd.sh
```

The script sets `VLLM_USE_V1=0` (required for Qwen3 compat with vllm 0.8.2).

**Output**: `OpenVul/results/{mode}/C/NPD/{category}/{variant}__{mode}__n8__C_NPD_{category}.json`. Category is inferred from the basename of `--output-dir`.

**Why not a submodule**: only `run.py` is needed. The model is fetched from Hugging Face at first use. No upstream to track.

---

## 4. Where Things Live

| Thing | Path | Generated? |
|-------|------|------------|
| Safe source variants | `benchmark/{Lang}/{Bug}/safe/{variant}/` | committed |
| Attack payloads (text) | `automatic/texts/{lang}_{bug}.json` | committed |
| Attack benchmark (RepoAudit) | `RepoAudit/benchmark/{Lang}/{Bug}/{category}/{variant}/` | by `setup_benchmark.sh` |
| Attack datasets (VulnLLM-R / VulTrial) | `{VulnLLM-R,VulTrial}/datasets/{Lang}/{Bug}/{category}/{variant}/{c,python}/` | by `setup_benchmark.sh` |
| Attack datasets (OpenVul) | `OpenVul/datasets/C/NPD/{category}/{variant}/c/` | by `setup_benchmark.sh` |
| Defense source caches | `defenses/texts/{D3,D4,D5}_labeled/` | by `screen_defenses.sh` |
| Defense benchmarks | `RepoAudit/benchmark-defense/`, `VulnLLM-R/datasets-defense/` | by `setup_defenses.sh` |
| Results | `{system}/result(s)*/...` | by per-system run scripts |
