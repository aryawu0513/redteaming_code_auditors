# CVE NPD Benchmark (cvebench_full)

A benchmark of **128 null-pointer-dereference (NPD) vulnerabilities** derived from real CVE fix commits. Each sample is an LLM-generated vulnerable reimplementation of a function whose NPD bug was fixed in a public CVE patch. The vulnerabilities are confirmed by a blind LLM judge and by patching the attacker's code into the real repo and passing the original test suite.

## Motivation

Existing vulnerability detection benchmarks either use synthetic bugs or rely on the original vulnerable code verbatim from CVE databases. This dataset takes a different approach: an attacker model (Qwen3-27B) independently reimplements each fixed function in a way that reintroduces a null-pointer dereference, without being told where the NPD is. A blind judge (GPT-4o) then verifies the NPD exists independently — without any hint about where the attacker placed it. This produces clean, diverse, model-generated NPDs grounded in real-world vulnerability patterns.

## Construction pipeline

1. **CVE fix commits**: collected functions where a CVE patch removed a null-pointer dereference
2. **Repo validation**: each repo is cloned at the fix commit and its test suite must pass (confirms repo health)
3. **Context extraction**: tree-sitter extracts the target function, same-file helpers, cross-file helpers, and local project headers
4. **Task generation**: GPT-4o-mini writes a natural-language spec for the function; the target body is replaced with a `// TODO` stub
5. **Attacker generation**: Qwen3-27B fills in the stub, implementing the function without null checks and marking its intended NPD site with `/* NPD site */`
6. **Patch-and-test**: the attacker's body is spliced into the real repo, recompiled, and the test suite is run — only samples that compile and pass tests are kept
7. **Blind judge**: the `/* NPD site */` marker is stripped before judging; the judge independently determines whether an NPD exists and identifies the dereference line

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `code` | string | Full code passed to the detector: `// context\n<context>\n\n// target function\n<target_function>` |
| `context` | string | Everything before the target function in the source file, plus `raw_auxiliary.cc` (cross-file helpers) prepended if present |
| `target_function` | string | The target function definition and everything after it in the source file |
| `function_name` | string | Name of the vulnerable function |
| `deref_line` | string | Verbatim line of code where the attacker placed the null dereference (first non-empty line after `/* NPD site */` in the attacker's output) |
| `caller` | string | Same as `function_name` (reserved for call-graph context; currently always the target itself) |
| `file_name` | string | `solution.c` or `solution.cc` depending on language |
| `CWE_ID` | list[string] | Always `["CWE-476"]` (null pointer dereference) |
| `RELATED_CWE` | list[string] | Always `[]` |
| `stack_trace` | string | Always `""` (not available for LLM-generated code) |
| `target` | int | Always `1` (all samples are vulnerable) |
| `language` | string | `"c"` or `"cpp"` |
| `dataset` | string | `"cve-npd-bench"` |
| `idx` | int | Index within this dataset |
| `slug` | string | Unique sample identifier, e.g. `NPD-CVE-0006` |
| `variant` | string | Always `"CLEAN"` (no annotation injected) |
| `same_implementation` | bool\|null | Judge's assessment: does the attacker's implementation have the same overall logic as the original CVE-fixed code? |
| `same_npd_site` | bool\|null | Judge's assessment: is the NPD at the same logical location as in the original buggy code? |
| `npd_site_match` | bool | Whether `deref_line` (attacker-marked) and `generated_npd_line` (judge-found) refer to the same dereference (substring match). True for 108/128 samples (84%). |

## Notes on `same_implementation` and `same_npd_site`

These are informational fields set by the blind judge after confirming an NPD exists. They are not gates — all 128 samples have a confirmed NPD regardless of these values.

- `same_implementation=True` means the attacker wrote code structurally similar to the original CVE buggy version. `False` means the attacker found a different way to introduce an NPD.
- `same_npd_site=True` means the NPD occurs at the same logical point in the function as in the original bug. `False` means the NPD is at a different location.

Both fields are `null` only for samples marked `broken` or `not_vulnerable` by the judge, which are excluded from this dataset.

## Statistics

- 128 total samples
- Languages: C and C++
- Sources: real CVE fix commits across diverse open-source projects
- 108/128 (84%) have matching attacker and judge NPD lines
- All 128 pass the original repo test suite with the attacker's implementation
