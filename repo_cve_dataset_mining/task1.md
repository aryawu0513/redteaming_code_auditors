The goal of this benchmark is to evaluate LLM-based vulnerability auditors on a hard but realistic class of bugs: null pointer dereferences that arise naturally from correct-looking code. The key property we need is that when a model is given a coding task and implements it naively, it will naturally produce pointer-manipulating code. The attacker will work then, generating code that intentially omit the NPD guard and produce buggy code with camouflaging attack payloads. 

The benchmark then lets us test whether LLM-based auditors — RepoAudit, VulnLLM-R — can catch these omissions in model-generated code. MegaVul and CVEFixes give us a large corpus of real-world C/C++ NPD bugs with commit metadata already attached, which means we can automate the mining step that was done manually for the sofa-pbrpc pilot. The goal of this filtering pipeline is to go from hundreds of raw CWE-476 entries down to high-quality candidates that satisfy this property: single-function fixes, simple enough to stub out and give to a model as a coding task, with the NPD detectable by CodeQL so the downstream auditor evaluation has a reliable grading signal. 
Once the set are done, we will run the attacker agent to produce the initial payload dataset, which contains one baseline file that have the npd bug in without any attack payload, and 10 attack file.
We will then do a final filter to make sure all 4 systems can realiably detect the bug in the baseline file.


**Task: Filter MegaVul/CVEFixes CWE-476 entries to viable benchmark sites**

We have confirmed both datasets have CWE-476 C/C++ entries. Now we need to filter down to ones that will actually work as benchmark tasks — i.e., functions simple enough to stub out and give to a model as a coding task, where the NPD is detectable by CodeQL.

Then. we really really need to decide on one to use. not both. 

**The filter criteria, in order of cheapness:**

**Filter 1: Single file touch** (free, no GitHub call)

The fix commit must touch exactly one file. Multi-file commits are almost certainly refactors or architectural changes, not simple null guard insertions. Check `file_paths` — drop anything with more than one entry.

**Filter 2: Small diff** (free, no GitHub call)

Lines added in the diff must be <= 5. Anything larger is not a simple null guard. Both datasets have diff stats available without pulling the full file.

**Filter 3: Pull the full file from GitHub** (one GitHub API call per entry)

Using `repo_url` + `commit_hash` + `file_path`, fetch the full source file at the buggy commit. Drop entries where:
- the file is over 1000 lines (too large to give as context)
- the file doesn't compile standalone with a simple `gcc -c` (too many missing dependencies)

**Filter 4: CodeQL positive control** (most expensive, run last)

Run CodeQL `cpp/missing-null-test` on the full file. Drop entries where CodeQL doesn't flag anything — these are interprocedural blind spots that won't be gradeable in the downstream experiment.

**Output**

For each surviving entry, write a `candidate.json` with:
```json
{
  "source": "megavul" or "cvefixes",
  "cve_id": "...",
  "repo_url": "...",
  "commit_hash": "...",
  "file_path": "...",
  "func_name": "...",
  "commit_message": "...",
  "vulnerable_code": "...",
  "full_file": "..."
}
```

These candidates feed directly into the `generate_task.py` step to produce `starter.cc`, `task.md`, and `tests.cc`.

**Implementation notes**

- Run filters 1 and 2 in a single streaming pass — no GitHub calls at all, very fast
- Rate-limit GitHub calls in filter 3 (max ~60/hr unauthenticated, ~5000/hr with a token)
- Run filter 4 only on whatever survives filter 3 — CodeQL is slow, don't waste it
- Both datasets can be streamed from HuggingFace — no downloads needed (`pip install datasets`)
