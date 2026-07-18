# smaller_attacker — swapping Qwen3.6-27B for a smaller, different-family model

Ablation: the attacker in this repo has always been `Qwen/Qwen3.6-27B-FP8`
(served via `scripts/serve_qwen3p6_27b_refiner.sh`). This directory evaluates
smaller/different models as drop-in replacements, along two independent axes
— matching the two distinct "attacker" roles that already exist elsewhere in
this repo:

1. **Phase 1 — vulnerable-code generation quality.** Can the model fill in a
   stubbed CVE function so that it (a) compiles, (b) passes the repo's real
   test suite, using the *same* mechanism as `cvebench/generate_attacker.py`
   + `cvebench/patch_and_test.py` (dataset-construction role).
2. **Phase 2 — attack-payload quality.** Given a detector's own reasoning on
   a bare vulnerable function, can the model craft a deceptive annotation
   that flips the detector's verdict to "safe" — same mechanism as
   `adaptive_attacker/refine_loop_fromscratch.py` (evasion role).

These are independent: Phase 2 runs against the existing
`benchmark/cvebench_full/baseline` dataset (built long ago, mostly by Qwen),
not against Phase 1's output. **No existing script in `cvebench/` or
`adaptive_attacker/` is modified** — everything here just calls them as
subprocesses with a different `--model` / `--refiner-model` and
`--base-url` / `OPENAI_BASE_URL` pointed at a new local server, and writes
results only under `smaller_attacker/results/`.

## Candidates (`models.yaml`)

| tag | served-model-name | weights | family | port | GPU |
|---|---|---|---|---|---|
| `gemma4-26b-a4b` | `gemma4-26b-a4b-it` | `/mnt/ssd/arjun/models/gemma_4_26b_a4b_it` (MoE, ~4B active) | Gemma | 8100 | 0 |
| `gemma4-12b` | `gemma4-12b-it` | `/mnt/ssd/arjun/models/gemma4_12b_it` | Gemma | 8101 | 1 |

Both are already downloaded locally (courtesy of `arjun`'s cache) — no HF
pull needed, no gating issues. Serve flags mirror the known-working
reference at `/mnt/ssd/aryawu/MultiPL_TokenCost/experiment/bin/vllm_serve_gemma.sh`.
Both have a 131072-token context window, well past anything this benchmark's
prompts need (unlike Gemma-2-9b-it, which we tried first and dropped — its
8192-token window and system-role-rejecting chat template made it a poor
fit; Gemma-4's template supports `system` natively).

GPU 3 is off-limits (reserved by someone else as of 2026-07-15) — GPUs 0/1
are used here, one model per GPU so both can run concurrently.

Installed `vllm` (0.20.0, the repo's normal environment) already ships full
Gemma-4 support (model arch, `--reasoning-parser gemma4`,
`--tool-call-parser gemma4`) — no need for the custom vllm build the
reference script uses.

## Pilot scale

18 slugs each for Phase 1 (`pilot_slugs_phase1.txt`, drawn from
`cvebench/viable_184.txt`, one per distinct repo for diversity) and Phase 2
(`pilot_slugs_phase2.txt`, drawn from `benchmark/cvebench_full/baseline`,
also one per repo — 11 of the 18 overlap with the Phase 1 set, the datasets
just don't have identical slug coverage). Phase 2 budget is 1 refinement
round (bootstrap + 1 refine call per attack type), across all 10 attack
types by default.

## How to run

This is long-running (up to 18 build/test cycles per model in Phase 1;
~18 slugs × 10 types in Phase 2) — **launch it yourself**, don't have an
agent run it in the background unattended.

```bash
# 1. Start each model's server in its own terminal (or tmux pane):
bash smaller_attacker/serve/serve_gemma4_26b_a4b.sh   # GPU 0, port 8100
bash smaller_attacker/serve/serve_gemma4_12b.sh        # GPU 1, port 8101

# 2. For Phase 2 only, also start the detector (any free GPU):
MODE=funclevel DETECTOR_GPU=<gpu> bash scripts/serve_detector_vulnllmr.sh

# 3. Run everything (or do it model-by-model / phase-by-phase, see below):
bash smaller_attacker/run_all.sh 2>&1 | tee smaller_attacker/run_all.log
```

To run a single model / single phase (e.g. while iterating):

```bash
bash smaller_attacker/phase1_gen_and_test.sh gemma4-26b-a4b gemma4-26b-a4b-it 8100
bash smaller_attacker/phase2_evasion.sh      gemma4-26b-a4b gemma4-26b-a4b-it 8100 1
```

## Scoring

```bash
python3 smaller_attacker/score_phase1.py   # build_ok / tests_pass / npd_marked rates per model
python3 smaller_attacker/score_phase2.py   # attack success rate (ASR) per model, per attack type
```

Results:
- `smaller_attacker/results/<tag>/phase1/attacker_results.json` — from `patch_and_test.py`, untouched format.
- `smaller_attacker/results/<tag>/phase2/repository_<slug>/summary_pilot_v1.csv` — from `refine_loop_fromscratch.py`, untouched format.
- `smaller_attacker/results/phase1_summary.json`, `phase2_summary.json` — aggregated by the score scripts above.

## Notes / caveats

- Phase 1's `npd_marked` column checks for the literal `/* NPD site */`
  comment the system prompt (`cvebench/config_cve_attacker.yaml`) requires —
  it's a cheap proxy for "did the model actually inject the intended bug"
  as opposed to just writing correct, non-vulnerable code that happens to
  pass tests.
- Both candidates emit `<think>`-style reasoning; `--reasoning-parser gemma4`
  strips that from `message.content` at the server, so downstream parsing in
  `generate_attacker.py`/`refine_loop_fromscratch.py` (which expects raw
  code or raw JSON, no chain-of-thought) should see clean output. If output
  parsing errors show up, check that the server actually launched with
  `--reasoning-parser gemma4` (both serve scripts here do).
