# Attacker Strategy Notes

Goal: maximize samples where attacker-patched code compiles + passes test suite (reproduces NPD).  
Current baseline: 39/183 pass after round 1 (one-shot, raw_primary + auxiliary only).

---

## What we tried

### Round 1 — One-shot, no headers
- Model: Qwen/Qwen3.6-27B-FP8, temperature=0, one shot
- Context: task.md + starter.cc (raw_primary stubbed) + raw_auxiliary.cc
- Result: **39 pass / 76 build-fail / ~68 test-fail** (out of 183)
- Main failure mode: hallucinated struct members and function names the model couldn't see

---

## What to try next (ordered by effort)

### R2 — Add project headers to context  ← NEXT
- **What**: run `extract_headers.py` to pull `#include "..."` headers from repo clone (1 level recursive), add as `raw_headers.h` to attacker prompt
- **Why**: eliminates hallucinated struct layouts and API names — the model can see actual types
- **Effort**: low (already implemented)
- **Expected gain**: most of the 76 build-fail cases

### R3 — Retry with compiler error feedback
- **What**: for samples that still build-fail after R2, send a second message with the exact `error_output` from `attacker_result.json` and ask the model to fix only the errors
- **Why**: even with headers, some errors may remain; the compiler message is a precise signal
- **Effort**: low (add `--retry-failed` flag to `generate_attacker.py`)
- **Expected gain**: catches remaining hallucinations that headers didn't resolve


### R4 — Mini-SWE-agent on full cloned repo (Docker)
- **What**: spin up a Docker container with the full repo clone pre-built; give the agent a shell, task.md, and the target function stub. Agent can `cat` any file, `grep` for types/symbols, compile incrementally, read errors, and iterate until tests pass or budget exhausted. Output is the final patched source file diff.
- **Why**: no context limit problem — agent discovers what it needs by exploring; compile-and-fix loop is guaranteed to make progress on build failures; agent can also run the test suite itself and iterate on test failures
- **Effort**: high — need a Docker image per repo (or reuse the existing clone), an agent harness that exposes shell + task.md, and a way to extract the final function from the diff
- **Expected gain**: very high — should handle any build-fail case and many test-fail cases
- **Cost**: minutes per sample; run only on failures after R2/R3



---

## Priority order

1. R2 (headers) — run now
3. R3 (error feedback retry) — for remaining build-fails after R2
5. R4 (mini-SWE-agent) — if still short of 100
