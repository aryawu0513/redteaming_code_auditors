# scripts/

Sample scripts to run the full pipeline. Adapt env vars to change bug type / language.

## Setup (run once after cloning)

```bash
source RepoAudit/.venv/bin/activate
bash scripts/setup_benchmark.sh
```

Populates `RepoAudit/benchmark/` and `VulnLLM-R/datasets/` from:
- `benchmark/` (safe source codes)
- `automatic/texts/` (attack payloads)

## Run RepoAudit

```bash
source RepoAudit/.venv/bin/activate
export ANTHROPIC_API_KEY=...

bash scripts/run_repoaudit_c_npd.sh         # C/NPD (default)

# UAF:
BUG_TYPE=UAF BENCHMARK="$(pwd)/RepoAudit/benchmark/C/UAF" \
    bash scripts/run_repoaudit_c_npd.sh

# Python/NPD:
LANGUAGE=Python BUG_TYPE=NPD FILES='*.py' \
    BENCHMARK="$(pwd)/RepoAudit/benchmark/Python/NPD" \
    bash scripts/run_repoaudit_c_npd.sh
```

Results land in `RepoAudit/result/dfbscan/{model}/NPD/{lang}/{category}/{timestamp}/`.

## Run VulnLLM-R

```bash
source VulnLLM-R/.venv/bin/activate
nvidia-smi                             # pick a free GPU
export CUDA_VISIBLE_DEVICES=<id>

bash scripts/run_vulnllm_c_npd.sh      # C/NPD (default)

# UAF:
DATASET_ROOT="$(pwd)/VulnLLM-R/datasets/C/UAF" \
RESULTS_ROOT="$(pwd)/VulnLLM-R/results/C/UAF/policy" \
VARIANTS="freeitem dropconn relogger rmentry" \
    bash scripts/run_vulnllm_c_npd.sh

# Python/NPD:
DATASET_ROOT="$(pwd)/VulnLLM-R/datasets/Python/NPD" \
RESULTS_ROOT="$(pwd)/VulnLLM-R/results/Python/NPD/policy" \
VARIANTS="finduser makeconn parseitem loadconf" \
LANGUAGE=python \
    bash scripts/run_vulnllm_c_npd.sh
```

Results land in `VulnLLM-R/results/{lang}/{bug}/policy/{category}/`.
