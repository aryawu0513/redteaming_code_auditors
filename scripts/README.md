# scripts/

Scripts for running the from-scratch adaptive attack on cvebench_full.

## Setup (run once after cloning)

```bash
uv sync
source .venv/bin/activate
```

## Serving (start before launching an attack)

Every attack run needs two servers: the **Qwen refiner** (always) and the
**detector** (for systems that run locally — OpenVul and VulnLLM-R).

```bash
# Refiner — always required (port 8007)
bash scripts/serve_qwen3p6_27b_refiner.sh

# Detector — pick the one matching your attack script
bash scripts/serve_detector_openvul.sh          # port 8009
bash scripts/serve_detector_vulnllmr.sh         # port 8008  (add MODE=funclevel for funclevel mode)
bash scripts/serve_detector_repoaudit.sh        # port 8008
bash scripts/serve_detector_vultrial.sh         # port 8008
bash scripts/serve_detector_vulrag.sh           # port 8009
```

RepoAudit and VulTrial call the OpenAI API directly — no local detector server needed,
only the Qwen refiner.

## Running an attack

Each script is self-contained with usage notes at the top.
Set `OPENAI_API_KEY` before running (used for detector or refiner API calls).

```bash
# VulnLLM-R funclevel — budget 5 (default)
bash scripts/run_fromscratch_cvebench_full_vulnllmr_funclevel.sh

# VulnLLM-R funclevel — budget 10
bash scripts/run_fromscratch_cvebench_full_vulnllmr_funclevel_b10.sh

# OpenVul
bash scripts/run_fromscratch_cvebench_full_openvul.sh
bash scripts/run_fromscratch_cvebench_full_openvul_b10.sh

# RepoAudit (o3-mini)
bash scripts/run_fromscratch_cvebench_full_repoaudit_o3mini.sh

# VulTrial
bash scripts/run_fromscratch_cvebench_full_vultrial.sh

# Vul-RAG
bash scripts/run_fromscratch_cvebench_full_vulrag.sh
```

Results land in `adaptive_attacker/results/<system>/repository_<slug>/`.
Already-completed slugs are skipped automatically on resume.

## One-off scripts

`scripts/oneoff/` contains stale/exploratory scripts kept locally for reference.
It is git-ignored and not part of the active workflow.
