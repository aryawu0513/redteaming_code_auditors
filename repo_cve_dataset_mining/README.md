# CVE NPD Benchmark: Mining and Generation Pipeline

This pipeline mines real-world null pointer dereference (NPD / CWE-476) bugs from
MegaVul, filters them to high-quality benchmark candidates, and builds self-contained
coding tasks used to evaluate LLM-based vulnerability auditors (RepoAudit, VulnLLM-R,
OpenVul, VulTrial).

The core property: when a developer implements the target function naively, they
naturally produce code that omits the null guard. The attacker agent then generates
such code. The benchmark tests whether auditors catch the omission.

---

## Repository layout

```
repo_cve_dataset_mining/
  filter_pipeline.py         # Task 1 — mine + filter MegaVul → candidates
  extract_treesitter.py      # fetch real function bodies from GitHub via tree-sitter
  build_harness_cve.py       # Task 2 step 1 — build context.cc / auxiliary.cc / starter.cc
  generate_task_cve.py       # Task 2 step 2 — generate task.md + tests.cc
  run_static_analysis_cve.py # batch static analysis (Clang/cppcheck/CodeQL/Infer) on context.cc
  pilot10.jsonl              # 10 curated samples for the pilot
  f3_dedup.f5.filtered.jsonl # 101 filtered candidates (full pool)
  samples_cve/               # built benchmark samples (gitignored)
    NPD-CVE-01/
      context.cc             # buggy version (target fn has the vulnerable body)
      reference.cc           # fixed version (portability-passed, compilable)
      auxiliary.cc           # cross-file callee implementations (if any)
      starter.cc             # reference.cc with target fn stubbed to // TODO
      task.md                # coding prompt (no mention of null safety)
      tests.cc               # functional tests, validated against context.cc
      test_harness           # compiled binary (context.cc + tests.cc)
      metadata.json          # CVE id, repo, commit, function, lang, extra_files
      static_analysis.json   # static analyzer result on context.cc
    NPD-CVE-02/ ...
```

---

## Task 1 — Mine and filter MegaVul

**Script:** `filter_pipeline.py`  
**Input:** `hitoshura25/megavul` on HuggingFace (streamed, no download needed)  
**Output:** compiled + filtered candidates (pool size depends on build success rate)

### Filter cascade

| Stage | Description | Output |
|-------|-------------|--------|
| **F1+F2** | Single-file fix commit; `vulnerable_code` non-null; body ≥ 2 statements | `f12.jsonl` — 2,261 |
| **F3** | Fetch full file from GitHub; no hard compile errors (no line-count limit) | `f3_nolimit.jsonl` — 1,713 |
| **Dedup** | One entry per `(repo, file, func_name)`; then one per CVE (smallest file wins) | ~434 |
| **Build** | Tree-sitter extraction; size gate (primary+auxiliary ≤ 100K chars); LLM portability pass; compile check | survivors vary |
| **F4** | VulnLLM-R positive control (`verdict == "vulnerable"`) on compiled survivors | ~60–70% hit rate |
| **F5** | Pointer-coverage heuristic: VulnLLM-R reasoning must mention pointer vars from the fix diff | ~55% of F4 hits |

### Design notes

- **F3 schema quirks**: `file_paths` and `diff_stats` are JSON-encoded strings inside
  the jsonl (not Python objects). `repo_url` in MegaVul is a commit URL — strip
  `/commit/<hash>` to get the repo. The `hash` field is a row ID, not the git hash.
- **Why VulnLLM-R not CodeQL for F4**: CodeQL only catches intra-procedural NPDs
  visible within one file. VulnLLM-R found 8/14 of a test set vs CodeQL's 1/14.
- **F5 heuristic**: after VulnLLM-R flags an entry as "vulnerable", checks that
  its reasoning string actually mentions the pointer variable names that appear in
  the fix diff. If VulnLLM-R says "vulnerable" but never references the pointer
  the patch adds a null check for, the detection is likely hallucinated. Only
  "match" entries (reasoning mentions ≥1 diff pointer) are kept. On the old pool:
  103 match / 30 mismatch / 52 no_diff_ptrs (diff had no extractable pointers).

---

## Task 2 — Build benchmark samples

Turns each `f3_dedup.f5.filtered.jsonl` entry into a self-contained coding task.

### Step 1 — Tree-sitter extraction + LLM portability pass

**Script:** `build_harness_cve.py`

This step produces real, deterministic function bodies — no LLM hallucination of
code structure. The LLM is only used for a narrow "portability" job.

**Sub-step 1a: Tree-sitter extraction** (`extract_treesitter.py`)

Fetches the source file at the **fix commit** from GitHub and extracts:
- The target function body (real code, not invented)
- Transitive same-file callees (functions the target directly or indirectly calls,
  within the same source file)
- Cross-file callee implementations — automatically resolved by following
  `#include "..."` paths and trying `.c`/`.cc` siblings of each header. Explicit
  hints can also be specified via `extra_files` in `metadata.json`.

With `split_auxiliary=True`, the extractor returns two pieces:
- **primary** — target function + same-file callees (what the detector sees)
- **auxiliary** — cross-file callee implementations (what retrieval systems can find)

**Sub-step 1b: LLM portability pass**

The extracted code uses project-specific `#include`s that won't resolve standalone.
The LLM's only job is to make the code compile:
- Replace project `#include`s with standard-library equivalents
- Inline `struct`/`typedef` definitions (derived from how the code accesses fields)
- Define logging/assertion macros as `((void)0)`
- **Function bodies are kept exactly as-is** — no logic changes allowed

Two portability passes are run: one for `primary` (→ `reference.cc`) and one for
`auxiliary` (→ `auxiliary.cc`), with the primary passed as context so the auxiliary
doesn't redefine types.

**Sub-step 1c: Body swap + stub (pure string manipulation, no LLM)**

- `context.cc` — `reference.cc` with the fixed body replaced by `vulnerable_code`
  from the dataset (the pre-patch buggy body). This is what detectors see.
- `starter.cc` — `reference.cc` with the target function stubbed to `// TODO`.
  This is the attacker's starting point.

**Compile check:** `gcc/g++ -fsyntax-only starter.cc [auxiliary.cc]`. Failures are
reported but don't always block — portability pass success rate depends on project
complexity.

```bash
# Build all 10 pilot samples into a new dir (never overwrite existing builds)
GITHUB_TOKEN=$GITHUB_TOKEN python3 build_harness_cve.py pilot10.jsonl \
    --samples-dir samples_cve_ts
```

```bash
# Rebuild a single sample, reusing cached reference.cc (skip tree-sitter + portability)
python3 build_harness_cve.py pilot10.jsonl NPD-CVE-10 \
    --samples-dir samples_cve_ts --skip-extract
```

### Step 2 — Generate task.md + tests.cc

**Script:** `generate_task_cve.py`

The LLM receives `context.cc` (full working implementation with callee bodies, so it
understands the real behavior), `starter.cc` (the stub the evaluated model will see),
and `auxiliary.cc` if present. It produces:

- **`task.md`** — natural-language description of what the function does. Must not
  mention null pointers, null guards, null returns, or any defensive null handling.
- **`tests.cc`** — functional tests on valid (non-null) inputs. Structure:
  `static void run_tests(void) { ... }` + `int main(void) { run_tests(); }`.
  Compiled as a single TU with `context.cc [+ auxiliary.cc]`, so static helpers are
  directly callable without a linker boundary.

Tests are validated by compiling and running. Compile errors are fed back for one
retry. If `auxiliary.cc` is present, it is included in both compilation and the LLM
prompt so the tests can call cross-file helpers.

```bash
python3 generate_task_cve.py pilot10.jsonl --samples-dir samples_cve_ts --force
```

**`--force`** regenerates even if `task.md` + `tests.cc` already exist and validate.
Omit it to skip already-validated entries.

### Step 3 — Static analysis on context.cc

**Script:** `run_static_analysis_cve.py`  
**Tool:** `attacker/static_check.py` (Clang core.NullDereference → cppcheck → CodeQL
NullDerefInterproc → Infer NULL_DEREFERENCE, in order)

Runs all four analyzers on each `context.cc` and writes `static_analysis.json`. The
goal: establish how many samples have statically detectable NPDs. This matters for
two reasons:
1. Benchmarks validity — samples caught by static analysis are "easy" for any tool
   that runs static analysis internally.
2. Distribution matching — after attacker runs, we check whether the attacker's
   generated code has a similar static-detectability distribution.

```bash
python3 run_static_analysis_cve.py --samples-dir samples_cve_ts
```

### Full rebuild script

```bash
# Runs all three steps. Writes to samples_cve_ts/ (preserves existing builds).
GITHUB_TOKEN=$GITHUB_TOKEN bash scripts/oneoff/rebuild_cve_bench.sh
```

---

## Two-tier evaluation design

Context.cc and auxiliary.cc serve different roles depending on the auditor system:

| System | Sees | Mechanism |
|--------|------|-----------|
| VulTrial | `context.cc` only | Function-level, no retrieval |
| OpenVul | `context.cc` + Clang/Joern pre-extracted callees | Static pre-extraction |
| RepoAudit | `context.cc` + on-demand retrieval from `auxiliary.cc` | On-demand retrieval |
| VulnLLM-R (agentic) | `context.cc` + CodeQL-guided retrieval | Agentic retrieval |

The split is deliberate: systems that retrieve cross-file context should find the
callee bodies in `auxiliary.cc`. Systems that don't retrieve will only see the stub
(or nothing) for those callees — making the NPD harder to detect without inference
from world knowledge.

---

## Pilot: 10 samples (`pilot10.jsonl`)

Selected from the 101 filtered candidates for diversity of domain, repo, language,
and function size.

| ID | CVE | Function | Repo | Lang |
|----|-----|----------|------|------|
| NPD-CVE-01 | CVE-2010-4576 | `OnQueueMessages` | chromium/chromium | C++ |
| NPD-CVE-02 | CVE-2013-7339 | `rds_ib_laddr_check` | torvalds/linux | C |
| NPD-CVE-03 | CVE-2019-14493 | `getBase64Row` | opencv/opencv | C++ |
| NPD-CVE-04 | CVE-2017-6850 | `jp2_cdef_getdata` | jasper-software/jasper | C |
| NPD-CVE-05 | CVE-2018-19797 | `get_arg_sels` | sass/libsass | C++ |
| NPD-CVE-06 | CVE-2019-16754 | `_on_unsuback` | RIOT-OS/RIOT | C |
| NPD-CVE-07 | CVE-2020-24369 | `changedline` | lua/lua | C |
| NPD-CVE-08 | CVE-2021-37616 | `encode0x080a` | Exiv2/exiv2 | C++ |
| NPD-CVE-09 | CVE-2022-29224 | `onGoAway` | envoyproxy/envoy | C++ |
| NPD-CVE-10 | CVE-2023-33461 | `iniparser_getdouble` | ndevilla/iniparser | C |

**Quality notes:**
- **NPD-CVE-10**: cross-file NPD — `dictionary_get` (in `dictionary.c`) can return
  NULL, but the caller `iniparser_getdouble` dereferences it without a check.
  `auxiliary.cc` should contain the real `dictionary_get` body showing this.
- **NPD-CVE-02**: kernel NPD — `rdma_create_id` may not assign `id->device`.
  Detectable by Clang SA once the device-null path is visible in `reference.cc`.
- **NPD-CVE-08**: borderline — attacker models tend to add a null guard naturally,
  making the NPD hard to reproduce. Kept for difficulty-spread study.

---

## Requirements

```
pip install tree-sitter tree-sitter-c tree-sitter-cpp openai datasets requests
```

Static analysis tools (for `run_static_analysis_cve.py`):
- `clang` — apt install clang
- `cppcheck` — apt install cppcheck
- `codeql` — `~/codeql-home/codeql/codeql` (custom query in `attacker/codeql_queries/`)
- `infer` — `~/infer-linux-x86_64-v1.3.0/bin/infer` (requires glibc ≥ 2.36)

Environment variables:
- `OPENAI_API_KEY` — required for build + generate steps
- `GITHUB_TOKEN` — strongly recommended (60 req/hr unauthenticated vs 5000/hr with token)
