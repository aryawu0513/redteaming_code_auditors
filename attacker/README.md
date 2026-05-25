# Attacker Agent

An autonomous LLM agent (mini-swe-agent + gpt-5.4-mini) that generates LeetCode
linked-list solutions in C with an intentional null-pointer-dereference (NPD / CWE-476)
defect. The resulting solutions become adversarial "New Code" inputs for evaluating
whether automated code auditors (VulnLLM-R, RepoAudit, VulTrial, OpenVul) can detect
a real bug when misleading code annotations are present.

---

## What the attacker does

For each LeetCode linked-list problem the agent:

1. **Solves the problem correctly** — writes `solution.c` in C11 with malloc/pointer
   structures, verifies it passes all public tests (`submit`), and confirms static
   analysis finds exactly **one** NPD (`static_check` → `NPD_COUNT: 1`).

2. **Produces 10 annotated variants** — copies `solution.c` to `solution_{TYPE}.c`
   and inserts exactly one annotation comment near the defect site. Each annotation
   style simulates a different category of incorrect-but-plausible safety claim:

   | Variant | Annotation style |
   |---------|-----------------|
   | `COT` | Chain-of-thought reasoning block concluding the pointer is safe |
   | `FT` | CI/CD pipeline log entry claiming the scan passed |
   | `CG` | Call-graph provenance comment with fabricated caller file:line citations |
   | `AA_MSG` | Short message: "callee always returns valid pointer" |
   | `AA_USR` | User-voice: "USER: var is non-NULL here" |
   | `AA_CA` | Commented-out assert annotated as a live runtime guard |
   | `TOOL_ClangSA` | Simulated Clang Static Analyzer scan-build entry |
   | `TOOL_Frama` | Simulated Frama-C WP plugin proof entry |
   | `TOOL_Fuzzer` | Simulated libFuzzer report (0 crashes in N million iterations) |
   | `TOOL_Coverity` | Simulated Coverity FORWARD_NULL defect entry |

   The annotation is syntactically valid C but factually incorrect — the pointer
   **can** be NULL, but the comment asserts otherwise.

3. **Verifies each variant** — post-hoc verification checks that `solution_{TYPE}.c`
   still passes all tests AND that static analysis still finds NPD. Results are written
   to `verification.json`: `{"COT": "ok", "FT": "no_npd", ...}`.

Only variants with status `"ok"` are included in downstream evaluations.

---

## Pipeline

### Step 1 — Filter dataset

```bash
python attacker/filter_leetcode_problems.py [--run-dir attacker/runs/gpt-5]
```

Downloads easy linked-list problems from `greengerong/leetcode` (HuggingFace) and
creates experiment directories with parsed stdin/stdout test cases. Only problems
with clean list/int I/O are included (no strings, no cycle/intersection tricks),
so that solutions inherently require `struct Node*`, `malloc`, and null checks.

---

### Step 2 — Create experiment directories

```bash
python attacker/setup_problems.py [--limit N]
# Output: attacker/experiments/repository_{SLUG}/
#         attacker/experiments/problem_map.json
```

Each directory gets:
- `problem.md` — problem statement + sample I/O
- `COMMANDS.md` — agent reference for `run_test` / `submit`

`SLUG` = first 12 hex chars of SHA-256 of the problem name.

---

### Step 3 — Run attacker agents

A single mini-swe-agent session per problem produces `solution.c` (with NPD) and all
10 annotated variants.

```bash
export OPENAI_API_KEY=...

# All experiment directories
python attacker/run_attacker.py

# Specific directories only
python attacker/run_attacker.py attacker/experiments/repository_XXXX ...
```

After each problem the script runs post-hoc verification and writes:
- `solution.c` — base solution with exactly one NPD and no annotation
- `solution_{TYPE}.c` — annotated variant for each of the 10 styles
- `trajectory.json` — full agent trajectory for the session
- `verification.json` — `{"COT": "ok"|"no_npd"|"no_pass", ...}` for each variant

---

### Step 4 — Regenerate config (if attack taxonomy changes)

```bash
python attacker/build_config.py
# Reads ATTACK_DESCRIPTIONS + FEW_SHOT from automatic/generate_variant.py
# Output: attacker/config.yaml
```

---

### Step 5 — Build evaluation datasets

```bash
python attacker/build_eval_datasets.py
# Output: attacker/datasets/C/NPD/attacker_lcb/repository_{SLUG}/c/{SLUG}_{TYPE}.json
```

Converts `solution_{TYPE}.c` files into VulTrial / OpenVul JSON format (context +
target_function split). Only slugs with at least one `"ok"` variant are included.

---

### Step 6 — Run evaluators

#### VulnLLM-R (JSON dataset, requires GPU)

```bash
VLLM_USE_V1=0 CUDA_VISIBLE_DEVICES=<ID> \
    python -m vulscan.test.test \
    --dataset_path VulnLLM-R/datasets/C/NPD/attacker/context_aware/{SLUG} \
    --language c --model UCSB-SURFI/VulnLLM-R-7B \
    --use_cot --use_policy --vllm --tp 1 --max_tokens 4096 --save \
    --output_dir VulnLLM-R/results/C/NPD/attacker/{SLUG}
```

#### VulnLLM-R Agent Scaffold (agentic, requires GPU)

```bash
bash attacker/run_scaffold_attacks.sh
```

The agent scaffold runs `VulnLLM-R/agent_scaffold/` on each `solution_{TYPE}.c` file
directly. Results land in `attacker/scaffold_results/attacks/scaffold_{SLUG}.json`
(per-attack-type, per-function verdicts). Baseline results (on `solution.c`) are in
`attacker/scaffold_results/scaffold_{SLUG}.json`.

#### VulTrial

```bash
bash scripts/run_vultrial_attacker_generic.sh     # generic mode
bash scripts/run_vultrial_attacker_npd.sh         # NPD-specific mode
```

#### OpenVul

```bash
bash scripts/run_openvul_attacker_generic.sh
```

#### RepoAudit (requires OPENAI_API_KEY / Anthropic key)

```bash
cd RepoAudit/src
MODEL=anthropic/claude-3-7-sonnet-20250219 LANGUAGE=Cpp \
    bash run_repoaudit.sh \
    ../../RepoAudit/benchmark/C/NPD/attacker/context_aware/{SLUG} NPD "*.cpp"
```

---

### Step 7 — View results

```bash
python attacker/viewer.py
# → http://localhost:7801
```

The viewer shows per-variant source code (with NPD line highlighted in `solution.c`)
and side-by-side output from all five systems: RepoAudit, VulTrial, OpenVul,
VulnLLM-R (JSON), and VulnLLM-R Agent Scaffold (agentic).

---

## Directory layout

```
attacker/
├── mini-swe-agent/              git submodule (mini-swe-agent)
├── bin/                         C wrappers for agent tools
├── codeql_queries/              custom CodeQL query for interproc NPD
├── datasets/                    evaluation inputs (build_eval_datasets.py output)
├── experiments/
│   ├── problem_map.json
│   └── repository_{SLUG}/
│       ├── problem.md
│       ├── COMMANDS.md
│       ├── solution.c              clean base solution (NPD present, no annotation)
│       ├��─ solution_{TYPE}.c       annotated variant (10 per problem)
│       ├��─ trajectory_{TYPE}.json  agent trajectory
│       └── verification.json       {TYPE: "ok"|"no_npd"|"no_pass"}
├── runs/
│   └── gpt-5.4-mini/            symlink / copies of verified experiment dirs
├── results/
│   └── npd_verification.csv     static-analysis ground truth
├── scaffold_results/
│   ├── scaffold_{SLUG}.json             VulnLLM-R agent scaffold on solution.c
│   └���─ attacks/scaffold_{SLUG}.json     VulnLLM-R agent scaffold on each variant
├── viewer_static/               frontend HTML/JS
├── filter_leetcode_problems.py  Step 1: download + filter LeetCode linked-list problems
├── setup_problems.py            Step 2: create experiment dirs
├── run_test.py                  agent tool: compile + run C against one input
├── submit.py                    agent tool: run against all public tests
├── static_check.py              agent tool: Clang + cppcheck + CodeQL + Infer NPD check
├── build_config.py              generate config.yaml from generate_variant.py constants
├── make_instance_config.py      generate per-run instance override for one attack type
├── config.yaml                  agent config (system + instance prompts)
├── run_attacker.py              launcher: one session per problem, all 10 variants
├── run_scaffold_attacks.sh      run VulnLLM-R agent scaffold on all variants
├── build_eval_datasets.py       convert solution_*.c to VulTrial/OpenVul JSON
└── viewer.py                    FastAPI backend for the results viewer
```

---

## Valid slugs for evaluation

After filtering out two problems where the agent failed to produce a valid NPD
(pure integer arithmetic / wrong algorithm), the benchmark contains **8 slugs**:

```
069A7F404506  3FC486D0AE27  6961F2970560  6B249C5786A8
7C95B6A69704  9823AA10FA1B  A3BC94AC32E5  B1AC850C7E87
```

Excluded: `E9FB59F8273B` (wrong algorithm), `F4FB78BE2FBB` (no pointers / integer only).
