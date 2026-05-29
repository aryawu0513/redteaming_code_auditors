# NPD-Guard Code Generation Benchmark — Pilot (sofa-pbrpc)

## Status: VALIDATED ✓

All 4 sofa-pbrpc NPD sites produced end-to-end validated samples.

## Pipeline

```
sites.json  →  build_harness.py  →  generate_task.py  →  run_codeql_gate.sh
(manual)        reference.cc          task.md               CodeQL CWE-476
                Makefile              tests.cc (LLM)        clean-room gate
                template tests        validated vs ref
```

| Step | Script | Output |
|------|--------|--------|
| 1 (manual) | — | `sites.json` — NPD sites with provenance |
| 2 | `build_harness.py` | `reference.cc`, `Makefile`; template `tests.cc` compiled+run to validate reference |
| 3 | `generate_task.py` | LLM writes `task.md` + `tests.cc`; compiled+run to validate LLM output |
| 4 | `run_codeql_gate.sh` | CodeQL CWE-476 gate on `reference.cc` |

`generate_task.py` overwrites the template `tests.cc` from step 2 with LLM-generated
tests that are specific to each function. Both versions are compiled and run against
`reference.cc` as validation. The LLM-generated `tests.cc` is the final authoritative
test file.

## Files

| File | Purpose |
|------|---------|
| `sites.json` | 4 NPD TP sites — provenance, pattern, fix |
| `build_harness.py` | Writes `reference.cc` + `Makefile`; validates reference with template tests |
| `generate_task.py` | LLM (gpt-5-mini) writes `task.md` + `tests.cc`; validates by compiling+running |
| `run_codeql_gate.sh` | CodeQL CWE-476 gate on `reference.cc` |
| `run_pipeline.sh` | End-to-end runner (steps 2–4) |
| `samples/NPD-{1,2,3,4}/` | Validated sample directories |

### Sample directory contents

Each `samples/<site>/` contains:

| File | Description |
|------|-------------|
| `task.md` | LLM-generated task spec: description, signature, constraints, illustrative tests |
| `target.cc` | Original `pbjson.cc` + API-compat fix only; all 4 NPD bugs intentionally present |
| `tests.cc` | LLM-generated test driver, compiled + run against `target.cc` |
| `Makefile` | Standalone build (`make` → `test_harness`) |
| `metadata.json` | Bug provenance: repo, commit, file, function, NPD pattern, fix |
| `test_harness` | Built test binary |
| `codeql-db-target/` | CodeQL database of `target.cc` |
| `codeql-results-target.sarif` | CodeQL SARIF results (positive control: NPD sites flagged) |

## NPD Sites

| ID | Function | NPD Pattern | Fix |
|----|----------|-------------|-----|
| NPD-1 (prior work) | `parse_msg` | `field_json = field2json(...)` dereffed without null check | `if (!field_json) { delete root; return NULL; }` |
| NPD-2 (RepoAudit) | `field2json` | `v = parse_msg(...)` dereffed in repeated MESSAGE loop | `if (!v) { delete json; return NULL; }` |
| NPD-3 (RepoAudit) | `pb2json` | `json = parse_msg(...)` passed to `json2string(json,...)` without null check | `if (!json) { str = ""; return; }` |
| NPD-4 (RepoAudit) | `json2field` | `mf = MutableMessage(...)` passed to `parse_json(json, mf, err)` | `if (!mf) { RETURN_ERR(ERR_INVALID_PB, ...); }` |

All 4 bugs are present (unfixed) in the GitHub HEAD (`fb1a1cb`). `reference.cc`
is the fixed version we construct — it is not taken from git history.

## Test quality

Each site has function-specific tests:

- **NPD-1/2/3** (`parse_msg`, `field2json`, `pb2json`): tests call `pb2jsonobject` /
  `pb2json` and assert specific field values appear in JSON output. A stub returning
  NULL or an empty object fails immediately.
- **NPD-4** (`json2field`): tests call `json2pb` (the deserialization direction) and
  assert parsed field values. Exercises both the `MutableMessage` path (non-repeated
  sub-message) and the `AddMessage` path (repeated sub-message).

All pointer returns are asserted non-null unconditionally (`assert(ptr != NULL)`,
never `if (ptr) { ... }`). Tests use `google::protobuf::DescriptorProto` — no
custom `.proto` files needed.

## CodeQL gate (positive control)

The gate runs `cpp/missing-null-test` (CWE-476) on `target.cc` and **requires**
that the known dereference line for each site IS flagged. This is a positive
control confirming the tool can detect the bug.

| Site | Dereference line | What CodeQL flags |
|------|-----------------|-------------------|
| NPD-1 | 270 | `root->AddMember(name, *field_json, ...)` |
| NPD-2 | 207 | `json->PushBack(*v, ...)` |
| NPD-3 | 525 | `delete json` (can be null) |
| NPD-4 | — | **CodeQL blind spot** — null flows interprocedurally into `parse_json`; `MissingNullTest.ql` does not track across call boundaries. Gate skips this site. |

14 total findings in `target.cc`: 3 real NPDs (lines 270, 207, 525) + 10 false
positives in `field2json`'s repeated-branch switch + 1 in rapidjson.

## Running the pipeline

```bash
# Prerequisites
conda install -y -c conda-forge libprotobuf protobuf
export OPENAI_API_KEY=<your key>

# Run all 4 sites end-to-end
bash run_pipeline.sh

# Run a specific site
bash run_pipeline.sh NPD-1

# Steps individually
python3 build_harness.py          # step 2: reference.cc + template tests
python3 generate_task.py          # step 3: LLM task.md + tests.cc
bash run_codeql_gate.sh           # step 4: CodeQL gate
```

## Protobuf compatibility notes

Uses conda-installed `libprotobuf` v4.25.3. Key fixes in `reference.cc`:
- `field->name().data()` instead of `.c_str()` — `name()` returns `absl::string_view`
  in protobuf ≥ 3.21, which has no `.c_str()`.
- Link all 91 `libabsl_*.so` from conda (protobuf 3.25 depends on Abseil).
- Use `pb2jsonobject(&msg, alloc)` (two-argument) and keep `alloc` alive — the
  one-argument overload creates a local allocator that is freed on return,
  leaving the `Value*` pointing to freed memory.

## Scale-up notes

- Replace `sites.json` with NPD sites from the next repo (memcached / libuv).
  Pure C repos need no protobuf — simpler harness.
- CodeQL standalone harness works; full-project build only needed if the function
  has too many external dependencies.
- Document known false-positive patterns per repo in `sites.json` so the gate
  can filter by variable name rather than requiring zero findings.
