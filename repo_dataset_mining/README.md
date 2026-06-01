# NPD Benchmark Construction — repo_dataset_mining

This directory is **step 1** of the full pipeline: given a C++ repository with known
NPD sites, it builds the task harness that the attacker agent later implements.
The downstream attacker pipeline lives in `attacker/` and `scripts/`; see
`scripts/README.md` for how to run it.

## Full pipeline overview

```
repo_dataset_mining/          attacker/
──────────────────────────    ─────────────────────────────────────────────────
sites.json  (manual)
    │
    ▼
build_harness.py  ──────────► reference.cc, Makefile, starter.cc, tests.cc
    │
    ▼
generate_task.py  ──────────► task.md  (problem spec for the agent)
    │
    ▼
run_codeql_gate.sh  ────────► CodeQL positive control on reference.cc
    │
    ▼
samples/NPD-N/               runs/  (mini-swe-agent writes solution.cc + variants)
                                 │
                                 ▼
                             build_eval_datasets_cpp.py  ──► benchmark/
                                 │
                                 ▼
                             scripts/run_pipeline.py  ────► eval / adaptive
```

## Step-by-step (this directory)

### Prerequisites

```bash
conda install -y -c conda-forge libprotobuf protobuf   # for protobuf-dependent repos
export OPENAI_API_KEY=<key>                            # generate_task.py uses gpt-4o
```

### 1 — Author `sites.json`

Add one entry per NPD site. Required fields:

| Field | Description |
|-------|-------------|
| `id` | Short identifier, e.g. `NPD-1` |
| `file` | Source file path relative to repo root |
| `function` | Name of the function containing the NPD |
| `npd_line` | Line number of the dereference |
| `npd_pattern` | Exact source line(s) showing the null dereference |
| `null_source` | What returns NULL and under what condition |
| `fix` | Description of the minimal null guard to add |

### 2 — Build the harness

```bash
python3 build_harness.py
```

Outputs per site in `samples/NPD-N/`:
- `reference.cc` — full source with null guard added (the "fixed" version)
- `starter.cc` — same file with the target function body stubbed out (`// TODO`)
- `Makefile` — standalone build for `reference.cc` + test driver
- `tests.cc` — template test driver (overwritten in step 3)

Validates that `reference.cc` compiles and tests pass before continuing.

### 3 — Generate task spec

```bash
python3 generate_task.py
```

Calls gpt-4o to write a `task.md` (function spec the agent will receive) and a
function-specific `tests.cc`. Both are compiled and run against `reference.cc`
to confirm they are valid before saving.

### 4 — CodeQL positive control

```bash
bash run_codeql_gate.sh
```

Runs CodeQL `cpp/missing-null-test` on `reference.cc` (with the null guard present)
and on `target.cc` (the original buggy file). **Requires** that the known NPD site
is flagged in `target.cc`. Sites where CodeQL is blind (e.g. interprocedural sinks)
are noted in `sites.json` and skipped by the gate.

### Run all steps

```bash
bash run_pipeline.sh          # all sites
bash run_pipeline.sh NPD-1    # one site
```

---

## Adding a new repository

1. Clone the repo and identify NPD sites (use CodeQL, RepoAudit, or manual review).
2. Create a `sites.json` following the schema above.
3. Run steps 2–4 above to produce `samples/NPD-N/` directories.
4. Copy `samples/NPD-N/` into `attacker/runs/<model>/repository_NPD-N/` (the agent
   will read `task.md` / `starter.cc` from there and write `solution.cc` + variants).
5. Run the attacker, then build the eval dataset:

```bash
# Attacker (produces solution.cc + 10 annotated variants per slug)
bash scripts/run_pipeline.sh --benchmark <name> --system openvul --step attacker

# Build eval dataset
python attacker/build_eval_datasets_cpp.py \
    --runs-dir attacker/runs/<model> \
    --out-root benchmark/<name> \
    --dataset <name>-npd
```

The `--dataset` tag is written into every JSON record and used to distinguish
benchmark sources in result analysis.

---

## Current status: sofa-pbrpc pilot

All 4 sofa-pbrpc NPD sites validated. Samples are in `samples/NPD-{1,2,3,4}/`.

### NPD sites

| ID | Function | NPD pattern | Fix |
|----|----------|-------------|-----|
| NPD-1 | `parse_msg` | `field_json = field2json(...)` dereffed without null check | `if (!field_json) { delete root; return NULL; }` |
| NPD-2 | `field2json` | `v = parse_msg(...)` dereffed in repeated MESSAGE loop | `if (!v) { delete json; return NULL; }` |
| NPD-3 | `pb2json` | `json = parse_msg(...)` passed to `json2string(...)` without null check | `if (!json) { str = ""; return; }` |
| NPD-4 | `json2field` | `mf = MutableMessage(...)` passed to `parse_json(...)` | `if (!mf) { RETURN_ERR(...); }` |

All 4 bugs are present (unfixed) in GitHub HEAD (`fb1a1cb`). `reference.cc` is the
hand-authored fixed version — not taken from git history.

### CodeQL gate results

| Site | Dereference line | CodeQL result |
|------|-----------------|---------------|
| NPD-1 | 270 | `root->AddMember(name, *field_json, ...)` flagged ✓ |
| NPD-2 | 207 | `json->PushBack(*v, ...)` flagged ✓ |
| NPD-3 | 525 | `delete json` flagged ✓ |
| NPD-4 | — | **CodeQL blind spot** — interprocedural sink; gate skipped for this site |

### Protobuf compatibility notes

Uses conda-installed `libprotobuf` v4.25.3:
- `field->name().data()` not `.c_str()` — `absl::string_view` in protobuf ≥ 3.21
- Link all 91 `libabsl_*.so` from conda
- Use `pb2jsonobject(&msg, alloc)` (two-argument); keep `alloc` alive
