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
# Full pipeline (attacker → build → eval → round0 → adaptive)
bash scripts/run_pipeline.sh --benchmark leetcodebench --system openvul --step all

# Just one step (debug)
bash scripts/run_pipeline.sh --benchmark leetcodebench --system openvul --step round0
```

Defaults:
- `--benchmark leetcodebench` (Qwen dataset)
- `--system` is required
- `--step eval`

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
