# scripts/

Sample scripts to run the full pipeline. Adapt env vars to change bug type / language.

## Setup (run once after cloning)

```bash
uv sync
source .venv/bin/activate
```

## Unified Pipeline (recommended)

Use the flag-driven launcher and run any step independently:

```bash
# Full pipeline (attacker → build → then a detector mode)
bash scripts/run_pipeline.sh --benchmark leetcodebench --system openvul --step all

# Just one step (debug)
bash scripts/run_pipeline.sh --benchmark leetcodebench --system openvul --step round0
```

Defaults:
- `--benchmark leetcodebench` (Qwen dataset)
- `--system` is required
- `--step eval`

### Pipeline shape: 2 prep steps + 3 parallel detector modes

The pipeline is really **three steps**, where the third is a choice of detector mode:

1. **attacker** — Qwen generates the annotated payloads.
2. **build** — assemble payloads into benchmark JSONs.
3. **run the detector** — pick one of three *parallel* modes (not a chain):
   - **`eval`** — run the detector once over baseline + context_aware; report ASR.
   - **`round0`** — same, but baseline-gated (skip context_aware if baseline misses).
   - **`adaptive`** — run the detector *and* refine in a loop.

`eval`, `round0`, and `adaptive` are **alternative things you do after `build`** — they
do not feed each other. In particular, the adaptive loop does **not** consume the saved
`eval`/`round0` result files: `refine_loop.py` performs its own round-0 detection
in-process (in `init_type`) to seed refinement, and writes its own `round_0.json`. The
saved `eval`/`round0` outputs are for ASR reporting and the baseline gate only.

(The `--step all` convenience runs attacker → build → eval → round0 → adaptive in
sequence, but that ordering is just "do everything"; the three detector modes are
independent and each re-runs detection from the built dataset.)

**Adaptive self-gates on baseline.** You do NOT need to run `round0` before `adaptive`.
The adaptive loop now does its own baseline pre-check: for each slug it first detects on
the CLEAN baseline record (the sibling `baseline/` dir of the `context_aware` dataset).
If the detector already calls the naked bug safe, the slug is skipped as `baseline_miss`
(written to `baseline_gate*.json` + `phase1_summary_partial.json`) — there is nothing for
an annotation to evade. So you can pass *candidate* slugs (even ones you're unsure about)
and let the loop drop the ones that don't pass; context_aware detection still happens only
once, inside the loop. Disable with `--no-baseline-gate` (flows through `run_pipeline.py`).

**Baseline-gated round0:** for OpenVul and VulnLLM-R, context_aware is only run
if the baseline sample is correctly flagged as vulnerable. You can also compute
round0 posthoc with:

```bash
python scripts/filter_round0.py \
  --baseline-dir OpenVul/results/npd/C/NPD/baseline \
  --context-dir  OpenVul/results/leetcodebench_qwen/npd/C/NPD/context_aware
```

## One-off Scripts

Temporary or system-specific runners live in `scripts/oneoff/`. The pipeline
launcher calls these internally; you generally shouldn't need to invoke them
directly.

## Serving Scripts (detectors for adaptive loop)

```bash
bash scripts/serve_detector_openvul.sh
bash scripts/serve_detector_vulnllmr.sh
bash scripts/serve_detector_repoaudit.sh
bash scripts/serve_detector_vultrial.sh
```
