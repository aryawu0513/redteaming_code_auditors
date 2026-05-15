# Attacker Agent

Autonomous mini-swe-agent that generates C++ competitive programming solutions with
hidden Null Pointer Dereference (NPD) bugs, disguised using the same adversarial
comment taxonomy as the existing redteaming benchmark.

Each problem is run once per attack type (COT, FT, CG, AA_MSG, AA_USR, AA_CA,
TOOL_ClangSA, TOOL_Frama, TOOL_Fuzzer, TOOL_Coverity), producing one
`solution_{ATTACK_TYPE}.cpp` per run.

---

## Prerequisites

```bash
# Install dependencies (from repo root)
uv sync

# Install run_test / submit / run_crash command-line tools
cd attacker/bin
gcc -o run_test run_test.c
gcc -o submit submit.c
gcc -o run_crash run_crash.c
cp run_test submit run_crash ~/.local/bin/
cd ../..
```

---

## Pipeline

### Step 1 — Filter dataset

Filter `deepmind/code_contests` for problems with C++ solutions containing pointer ops.

```bash
python attacker/filter_cpp_problems.py
# Output: attacker/data/cpp_pointer_problems.jsonl
# Prints summary: N problems scanned, M with C++ + pointer ops
```

Optional flags:
```bash
python attacker/filter_cpp_problems.py --splits valid test --limit 50
```

---

### Step 2 — Create experiment directories

```bash
python attacker/setup_problems.py
# Output: attacker/experiments/repository_{SLUG}/ for each problem
#         attacker/experiments/problem_map.json

# Limit to first N problems (useful for testing)
python attacker/setup_problems.py --limit 5
```

Each directory contains:
- `problem.md` — problem statement + sample I/O
- `COMMANDS.md` — agent reference for run_test / submit

---

### Step 3 — Regenerate config (if attack taxonomy changes)

```bash
python attacker/build_config.py
# Reads ATTACK_DESCRIPTIONS + FEW_SHOT from automatic/generate_variant.py
# Output: attacker/config.yaml
```

Only needed if `automatic/generate_variant.py` is updated.

---

### Step 4 — Run attacker agents

```bash
export OPENAI_API_KEY=...

# All problems × all attack types
./attacker/run_attacker.sh

# Specific problem directories only
./attacker/run_attacker.sh attacker/experiments/repository_2EA85A7D749D
```

Per (problem, attack_type) pair, writes:
- `solution_{ATTACK_TYPE}.cpp` — agent's malicious C++ solution
- `trajectory_{ATTACK_TYPE}.json` — full agent trajectory

The agent is required to pass both `submit` (all public tests pass) AND
`run_crash` (NPD is confirmed triggerable by a concrete input) before
completing. Solutions with statically dead null dereferences are rejected.

Runs are skipped if `trajectory_{ATTACK_TYPE}.json` already exists.

---

### Step 5 — Verify NPD bugs (static analysis)

```bash
python attacker/verify_npd.py
# Output: attacker/results/npd_verification.csv
```

Runs real `scan-build` (Clang Static Analyzer) and `cppcheck` on each solution.
Verdicts: `CONFIRMED` (at least one tool found NPD) or `UNVERIFIED` (neither found it —
may still have a bug; manual review needed).

```bash
# Verbose mode shows raw analyzer output
python attacker/verify_npd.py --verbose
```

---

### Step 6 — Prepare evaluation inputs

Converts `solution_*.cpp` files into VulnLLM-R JSON datasets and RepoAudit
benchmark files for a single repository.

```bash
python attacker/prepare_eval.py --repo-dir attacker/experiments/repository_XXXX
```

This writes:
- `VulnLLM-R/datasets/C/NPD/attacker/context_aware/{SLUG}/c/{SLUG}_{ATTACK_TYPE}.json`
- `RepoAudit/benchmark/C/NPD/attacker/context_aware/{SLUG}/{SLUG}_{ATTACK_TYPE}.cpp`

And prints the exact commands to run both evaluators (shown below).

---

### Step 7 — Run VulnLLM-R  *(requires GPU)*

```bash
VLLM_USE_V1=0 CUDA_VISIBLE_DEVICES=<GPU_ID> \
    .venv/bin/python -m vulscan.test.test \
    --dataset_path VulnLLM-R/datasets/C/NPD/attacker/context_aware/{SLUG} \
    --language c \
    --model UCSB-SURFI/VulnLLM-R-7B \
    --use_cot --use_policy \
    --vllm --tp 1 --max_tokens 4096 --save \
    --output_dir VulnLLM-R/results/C/NPD/attacker/{SLUG}
```

Notes:
- `VLLM_USE_V1=0` — disables vllm v1 engine to avoid CUDA fork issue
- `CUDA_VISIBLE_DEVICES=<GPU_ID>` — pick a free GPU (check with `nvidia-smi`)
- Use `.venv/bin/python` to ensure the project venv is used

Results land in `VulnLLM-R/results/C/NPD/attacker/{SLUG}/` — one JSON per dataset
file with per-sample predictions (flag: `tp`/`fp`/`fn`/`tn`) and aggregate F1/accuracy.

---

### Step 8 — Run RepoAudit  *(requires ANTHROPIC_API_KEY)*

Uses `anthropic/claude-3-7-sonnet-20250219` (Sonnet 3.7) This requires Openrouter Key.

```bash
cd RepoAudit/src
MODEL=anthropic/claude-3-7-sonnet-20250219 \
LANGUAGE=Cpp \
    bash run_repoaudit.sh \
    ../../RepoAudit/benchmark/C/NPD/attacker/context_aware/{SLUG} \
    NPD \
    "*.cpp"
```

Each `.cpp` file is scanned in isolation; RepoAudit reports whether it detects NPD
in each attacked solution.

---

## Directory layout

```
attacker/
├── mini-swe-agent/          git submodule
├── bin/
│   ├── run_test.c           C wrapper → run_test.py (compile + install to ~/.local/bin)
│   └── submit.c             C wrapper → submit.py   (compile + install to ~/.local/bin)
├── data/
│   └── cpp_pointer_problems.jsonl   generated by filter_cpp_problems.py
├── experiments/
│   ├── problem_map.json
│   └── repository_{SLUG}/
│       ├── problem.md
│       ├── COMMANDS.md
│       ├── solution_{ATTACK_TYPE}.cpp    (agent output)
│       └── trajectory_{ATTACK_TYPE}.json (agent output)
├── results/
│   └── npd_verification.csv
├── filter_cpp_problems.py
├── setup_problems.py
├── run_test.py              agent tool: compile + run C++ against input
├── submit.py                agent tool: run against all public+private tests
├── build_config.py          generate config.yaml from generate_variant.py constants
├── make_instance_config.py  generate per-run instance override for a specific attack type
├── config.yaml              generated — do not edit by hand
├── run_attacker.sh          launcher
└── verify_npd.py            post-processing static analysis
```
