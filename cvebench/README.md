# CVE NPD Benchmark Pipeline

End-to-end pipeline for building a null-pointer-dereference (NPD) benchmark from real CVE fix commits.

Input dataset: `f3_nolimit_dedup_func.slim.jsonl` — one row per CVE/function. Keeps `vulnerable_code` for reference but drops `full_file` and `_fixed_code` (superseded by repo clones and `raw_primary.cc`).

All per-sample outputs live in `samples_cve_fix/<pilot_id>/`.

---

## Stage 1 — Build viable dataset

Goal: for each CVE, produce a `task.md` + `starter.cc` that the attacker model can fill in. Only samples whose repo builds and passes its own test suite are kept.

### Step 1 — Clone repos and run test suite

```bash
python3 check_repo_testsuite.py \
    f3_nolimit_dedup_func.jsonl \
    --samples-dir samples_cve_fix \
    --clone-dir /tmp/cve_repos_fix
```

Clones each repo at the **fix commit**, runs the full build + test suite, writes per-sample sentinels:

| File | Meaning |
|------|---------|
| `repo_testsuite_pass` | All tests passed — sample is viable |
| `repo_testsuite_partial` | Some tests failed (excluded) |
| `repo_testsuite_fail` | Build or suite failed entirely |
| `repo_testsuite_none` | No test suite found |
| `repo_testsuite_result` | JSON with build/suite details |

Only `repo_testsuite_pass` samples continue downstream.

### Step 2 — Tree-sitter context extraction

```bash
python3 extract_context_cve.py \
    f3_nolimit_dedup_func.jsonl \
    --samples-dir samples_cve_fix \
    --clone-dir /tmp/cve_repos_fix
```

Both operate on the same repo clone. Tree-sitter extracts the target function and its dependencies; header extraction resolves the project headers it depends on:

| File | Content |
|------|---------|
| `raw_primary.cc` | Target function + same-file helper functions |
| `raw_auxiliary.cc` | Cross-file helper implementations (if any) |
| `raw_headers.h` | All local project headers the target file depends on (capped at 120K chars) |

Run `extract_headers.py` immediately after `extract_context_cve.py` — both need the same clone dir:

```bash
python3 extract_headers.py \
    f3_nolimit_dedup_func.jsonl \
    --ids-file viable_184.txt \
    --samples-dir samples_cve_fix \
    --clone-dir /tmp/cve_repos_fix
```

Resolves `#include "..."` (local includes only) one level deep. `raw_headers.h` is passed to the attacker so it knows struct layouts and available APIs without hallucinating.

### Step 3 — Size filter

Samples where `raw_primary.cc` + `raw_auxiliary.cc` exceed **124 000 chars** (~31K tokens) are marked `context_too_large` and excluded. Checked automatically by `generate_task_only.py`.

### Step 4 — Task generation

```bash
OPENAI_API_KEY=... python3 generate_task_only.py \
    f3_nolimit_dedup_func.jsonl \
    --samples-dir samples_cve_fix \
    --model gpt-5-mini \
    --workers 4
```

LLM (gpt-5-mini) sees `raw_primary.cc` + `raw_auxiliary.cc` and produces a natural-language spec. Builds outputs programmatically:

| File | Content |
|------|---------|
| `task.md` | Natural-language specification of the target function |
| `starter.cc` | `raw_primary.cc` with the target function body replaced by `// TODO` stub |

### Check counts

```bash
python3 pipeline_counts.py
```

Prints per-step counts and writes `viable_<N>.txt` — the list of pilot IDs that cleared all steps (testsuite_pass + raw_primary.cc + not context_too_large + task.md + starter.cc). Currently **184 samples**.

---

## Stage 2 — Generate and filter vulnerable code

Goal: have the attacker model write a vulnerable (NPD-containing) implementation for each viable sample, then filter to those that are real, compilable NPDs.

### Step 1 — Attacker code generation

```bash
python3 generate_attacker.py \
    f3_nolimit_dedup_func.jsonl \
    $(cat viable_184.txt | tr '\n' ' ') \
    --samples-dir samples_cve_fix \
    --model Qwen/Qwen3.6-27B-FP8 \
    --base-url http://localhost:8007/v1 \
    --workers 4
```

One-shot generation: the attacker model sees `task.md` + `starter.cc` + `raw_auxiliary.cc` + `raw_headers.h` and outputs the complete function implementation with a `/* NPD site */` marker indicating where the null dereference occurs.

Run in two rounds:
- **r1**: main run on all 184 viable samples
- **r2**: rerun on any sample whose r1 patch-and-test verdict was `fail` or `partial` (68 samples: 60 fail + 8 partial), giving the attacker a second chance

| File | Content |
|------|---------|
| `rounds/r1/<pid>/attacker_output.cc` | Attacker's implementation with `/* NPD site */` marker |
| `rounds/r2/<pid>/attacker_output.cc` | Second attempt for r1 fail/partial samples |

### Step 2 — Patch into repo and run tests

```bash
python3 patch_and_test.py \
    f3_nolimit_dedup_func.jsonl \
    $(cat viable_184.txt | tr '\n' ' ') \
    --samples-dir samples_cve_fix \
    --output-dir rounds/r1 \
    --clone-dir /tmp/cve_repos_fix \
    --build-timeout 300 --test-timeout 300
```

For each sample:
1. Extracts the target function body from `attacker_output.cc`
2. Splices it into the real repo source file
3. Incremental recompile (`cmake --build` or `make -j4`)
4. Runs the test suite (`ctest` or `make check`)
5. Restores original source (always, even on error)

| File | Content |
|------|---------|
| `rounds/r1/<pid>/attacker_result.json` | `{verdict: pass/partial/fail, build_ok, ...}` |

Only `pass` or `partial` verdicts continue. **184 viable → ~150 pass/partial** across r1+r2.

### Step 3 — Blind LLM judge

```bash
OPENAI_API_KEY=... python3 judge_cve_new.py \
    f3_nolimit_dedup_func.slim.jsonl \
    --rounds-dir rounds \
    --rounds r1 r2 \
    --out judge_r1r2.jsonl \
    --workers 4
```

Strips the `/* NPD site */` marker before sending to the judge (so it must find the NPD independently). Three-step verdict:

1. **broken?** — is the code non-compilable or obviously non-functional? If yes → `broken`, stop.
2. **NPD present?** — does the code contain a null pointer dereference? If no → `not_vulnerable`, stop. If yes → record `generated_npd_line` verbatim.
3. **Informational** (only if vulnerable): `same_npd_site` (does judge's NPD line match attacker's marked line?) and `same_implementation` (same logic as the original fix-commit code?).

Also records `attacker_npd_line` (the line the attacker marked with `/* NPD site */`) for posthoc comparison.

Output: `judge_r1r2.jsonl` — **128 vulnerable**, 14 broken, 3 not_vulnerable. 108/128 (84%) match between attacker and judge NPD lines.

---

## Stage 3 — Build benchmark

```bash
python3 build_benchmark.py \
    --judge   judge_r1r2.jsonl \
    --dataset f3_nolimit_dedup_func.slim.jsonl \
    --samples samples_cve_fix \
    --rounds  rounds \
    --out-root ../benchmark/cvebench_full
```

For each of the 128 verified vulnerable samples:
1. Takes best attacker output from r1/r2 (prefer `pass` > `partial`)
2. Strips `/* NPD site */` marker
3. Splices attacker body into `starter.cc` via `extract_body` + `splice_body`
4. Splits at the function definition → `context` (everything before) + `target_function`
5. Prepends `raw_auxiliary.cc` to context if present

Output schema is fully compatible with VulnLLM-R and OpenVul detector formats. Written to `benchmark/cvebench_full/baseline/repository_<pid>/<pid>_CLEAN.json`.

Its also on huggingface:
```py
python3 cvebench/push_to_hub.py \\
    --bench-root benchmark/cvebench_full \\
    --repo-id  AryaWu/cvebench_full \\
    [--private]
```

---

## Directory layout

```
cvebench/
├── f3_nolimit_dedup_func.slim.jsonl   # input dataset
├── viable_184.txt                     # stage 1 output: IDs that cleared all steps
├── judge_r1r2.jsonl                # stage 2 output: 128 verified vulnerable
├── samples_cve_fix/
│   └── NPD-CVE-XXXX/
│       ├── metadata.json
│       ├── repo_testsuite_pass        # step 1 sentinel
│       ├── raw_primary.cc             # step 2
│       ├── raw_auxiliary.cc           # step 2 (optional)
│       ├── context_too_large          # step 3 sentinel (excluded)
│       ├── raw_headers.h              # step 2
│       ├── task.md                    # step 4
│       └── starter.cc                 # step 4
├── rounds/
│   ├── r1/<pid>/attacker_output.cc    # stage 2 step 1
│   ├── r1/<pid>/attacker_result.json  # stage 2 step 2
│   ├── r2/<pid>/attacker_output.cc
│   └── r2/<pid>/attacker_result.json
├── check_repo_testsuite.py            # stage 1 step 1
├── extract_context_cve.py             # stage 1 step 2
├── extract_headers.py                 # stage 1 step 2
├── generate_task_only.py              # stage 1 step 4
├── pipeline_counts.py                 # counts + writes viable_N.txt
├── generate_attacker.py               # stage 2 step 1
├── patch_and_test.py                  # stage 2 step 2
├── judge_cve_new.py                   # stage 2 step 3
└── build_benchmark.py                 # stage 3
```
