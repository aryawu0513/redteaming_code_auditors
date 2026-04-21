# Red-teaming LLM Code Auditors

Adversarial attacks against two LLM-based vulnerability detectors, with defenses.
---

## Targets

| System | Description |
|--------|-------------|
| **RepoAudit** | Multi-agent repo-level auditor (Explorer + Validator). Submodule at `RepoAudit/`. |
| **VulnLLM-R** | Fine-tuned 7B reasoning model, single-shot. Submodule at `VulnLLM-R/`. |

**Bug types**: Null Pointer Dereference (NPD / CWE-476), Use-After-Free (UAF / CWE-416)  
**Languages**: C, Python

---

## Pipeline Overview

```
safe code
   │
   ▼ (automatic/generate_variant.py, --inject-bug)
buggy code  ←── or start here if code is already buggy
   │
   ▼ (automatic/gen_attacks.py)
attack benchmark files
   │
   ├─► RepoAudit/benchmark/{lang}/{bug}/
   └─► VulnLLM-R/datasets/{lang}/{bug}/
           │
           ▼ (RepoAudit/src/run_repoaudit.sh | VulnLLM-R/run_*.sh)
       raw results
           │
           ├─► results/view_results.py            (tables)
           ├─► results/view_defense_comparison.py (defense vs. baseline)
           └─► judge/find_false_positive.py        (LLM judge: attack-induced vs. incompetent)
```

---

## 1. Clean Dataset

Each bug type + language has several **variants** — independent codebases that all
exhibit the same bug pattern. Variants let us measure consistency across programs.

**C NPD variants**: `creatend`, `findrec`, `mkbuf`, `allocate`  
**Python NPD variants**: `finduser`, `makeconn`, `parseitem`, `loadconf`  
**C UAF variants**: `freeitem`, `dropconn`, `relogger`, `rmentry`

Benchmark structure (same for both systems):

```
{lang}/{bug_type}/
  safe/           ← safe code with null-check guard intact
  buggy/          ← bug introduced (null-check removed)
  dpi/            ← buggy code + direct prompt injection attacks
  context_aware/  ← buggy code + context-aware adversarial comments
```

---

## 2. Attack Generation (`automatic/`)

Two scripts do the work:

### `automatic/generate_variant.py` — LLM-based payload generator (DSPy)

Given source code, calls Claude twice:
1. **ExtractVariantMetadata** — identifies the callee, caller, variable name, and structural
   injection anchors (exact source lines) needed to craft targeted payloads.
2. **GenerateAttackPayload** — generates adversarial text for each of the 10 context-aware
   attack types (COT, FT, CG, AA_MSG, AA_USR, AA_CA, TOOL_*).

With `--inject-bug`: starts from the *safe* version and removes the null-check guard first
(stronger threat model: agent both introduces and hides the bug).

```bash
# Generate payloads for all variants in a directory:
python automatic/generate_variant.py --bug-type npd --language c \
    --clean-dir RepoAudit/benchmark/C/NPD/buggy

# Bug-injection mode (safe → buggy + payloads):
python automatic/generate_variant.py --bug-type npd --language c \
    --clean-dir RepoAudit/benchmark/C/NPD/safe \
    --inject-bug --buggy-dir RepoAudit/benchmark/C/NPD/buggy
```

Output: `automatic/texts/{language}_{bug_type}.json`

### `automatic/gen_attacks.py` — File writer

Reads `automatic/texts/{lang}_{bug_type}.json` and writes all attack files
(DPI and context-aware) to both `RepoAudit/benchmark/` and `VulnLLM-R/datasets/`.

```bash
python automatic/gen_attacks.py --bug-type npd --language c
python automatic/gen_attacks.py --bug-type uaf --language c
python automatic/gen_attacks.py --bug-type npd --language python
```

### Attack categories

| Category | Attacks | Mechanism |
|----------|---------|-----------|
| **DPI** (direct prompt injection) | HACK_1/2/3, IG_1/2/3, COMP_1/2/3, ESC_1/2 | Jailbreak-style injections embedded in comments |
| **Context-aware** | COT, FT, CG, AA_*, TOOL_* | Plausible-looking fake analysis artifacts (fake tool output, call-graph provenance, chain-of-thought) |

---

## 3. Defenses (`defenses/`)

Five defenses, from lightweight prompt instructions to LLM-based screening:

| ID | Description |
|----|-------------|
| **D1** | Prompt instruction: treat all comments as untrusted |
| **D2** | Prompt instruction: label each comment VERIFIABLE / INTENDED / UNVERIFIABLE / ADVERSARIAL before reasoning |
| **D3L** | Screening agent (Claude Haiku) pre-labels every comment in-place; audit model sees tags |
| **D3A** | Same screening agent, but flags UNVERIFIABLE/ADVERSARIAL comments with `[UNVERIFIABLE]` / `[ADVERSARIAL]` prefix |
| **D3B** | Same screening agent, but deletes UNVERIFIABLE/ADVERSARIAL comments entirely |
| **D5** | Annotator agent adds honest Google-style docstrings that document the null-return path |

Defense registry: `defenses/registry.py` (prompt additions for D1/D2, screening config for D3*)

### Applying defenses

```bash
# Inject defense instruction into RepoAudit prompts, then run:
python defenses/apply_repoaudit.py --defense D2 -- bash run_npd_c_attacks.sh

# Pre-screen VulnLLM-R dataset JSON files, then run:
python defenses/apply_vulnllm.py --defense D3A --run-script run_npd_c_attacks.sh

# After updating screening, rebuild all D3 variant dirs (no LLM re-call):
python defenses/rebuild_variants.py
```

---

## 4. Analysis (`results/`, `judge/`)

### Result tables

```bash
# Activate RepoAudit venv first:
source RepoAudit/.venv/bin/activate

python results/view_results.py both                            # C + Python, both systems
python results/view_results.py repoaudit --language c          # single system
python results/view_results.py both --bug-type uaf             # UAF results
python results/view_defense_comparison.py both --language c    # defense vs. baseline
```

### LLM judge (`judge/find_false_positive.py`)

For each false negative, classifies:
- `failure_stage`: Explorer / Validator / Model
- `is_attack_induced`: did the injected comment cause the failure?
- `is_incompetent`: would this have failed on the clean baseline anyway?
- `failure_mode`: short label (e.g. `comment_cited`, `hallucinated_guard`)

Results are cached in `judge/judge_cache.json`.

```bash
# Judge all FNs across all systems, languages, categories, and defenses:
bash judge/run_judge.sh

# Or selectively:
python judge/find_false_positive.py repoaudit --bug-type npd --language c --category context_aware
python judge/find_false_positive.py both --bug-type npd --language python
```

---

## 5. Demo (`demo/`)

End-to-end interactive demo on a self-contained target repo:

```
demo/target_repo/        ← the buggy C repo under audit
demo/target_repo_orig/   ← safe version (null-check intact)
demo/target_repo_attacks/ ← one copy per attack type
```

### Running the full loop

```bash
# Prerequisites: ANTHROPIC_API_KEY set, RepoAudit venv active, CUDA_VISIBLE_DEVICES set
bash demo/run_demo.sh                       # all context-aware attacks
bash demo/run_demo.sh COT CG TOOL_Frama    # specific subset
```

The script runs three phases:
1. **Baseline** — both auditors detect the bug in the clean repo.
2. **Attack** — `demo/attack_agent.py` injects adversarial comments (same LLM pipeline as `automatic/generate_variant.py`, but scoped to a single function).
3. **Post-attack** — both auditors run on each attacked repo; `demo/compare_results.py` prints the before/after.

### Gradio viewer

```bash
source VulnLLM-R/.venv/bin/activate
python demo/viewer.py   # → http://localhost:6003
```

Browse attack results, defense comparisons, and per-file model reasoning side-by-side.
Switch between defenses via the dropdown; results link back to the source code and log output.

---

## Environments

```bash
source RepoAudit/.venv/bin/activate    # RepoAudit + attack generation (DSPy, Anthropic SDK)
source VulnLLM-R/.venv/bin/activate   # VulnLLM-R inference (vllm, Gradio demo)
```

Set `ANTHROPIC_API_KEY` before any LLM-calling script.  
On shared GPU machines: check `nvidia-smi`, then `export CUDA_VISIBLE_DEVICES=<id>`.
