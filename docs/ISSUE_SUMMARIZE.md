# Attacker Pipeline — Issues & Attempts Summary

## Goal
Run a two-phase LLM attacker pipeline:
1. **Solver**: agent writes a correct C solution to a programming problem
2. **Injector**: agent removes one null pointer guard and adds an adversarial comment to fool code auditors

---

## Issue 1: Agent never exits on step limit (mini-swe-agent hangs)

**Symptom:** When the agent hits the step limit, mini-swe-agent calls `input()` interactively ("New step limit: "), blocking forever.

**Attempts:**
- Tried patching `mini-swe-agent/interactive.py` and `local.py` — user rejected this approach ("don't edit minisweagent")
- Tried various prompt tweaks to make the agent exit voluntarily

**Fix:** Pass `stdin=subprocess.DEVNULL` to the `subprocess.run` call launching mini. This makes `input()` raise `EOFError` immediately, matching the approach used in `MultiPL_TokenCost/mini_agent.py`.

---

## Issue 2: Agent exit trigger unreliable (injector loops on CANNOT_INJECT_NPD)

**Symptom:** When there was no injectable null pointer, the injector would keep looping instead of exiting cleanly.

**Fix:** Used `echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT` as the exit signal (same pattern as swebench's `cat patch.txt` flow). All exit paths in the injector prompt now end with this command.

---

## Issue 3: Solver never reports null pointer guards (NPD_guard.txt)

**Symptom:** Solver wrote `NO_NULL_GUARDS` even when the solution had `if (!mark) return 0` (an implicit null check on a `calloc` result).

**Root cause:** The original NPD_guard.txt prompt only listed explicit forms (`== NULL`, `!= NULL`, `== nullptr`) and missed implicit boolean guards (`if (!ptr)`, `if (ptr)`, ternary).

**Fix:** Expanded the NPD_guard.txt instructions to explicitly list:
- Implicit boolean forms: `if (!ptr)`, `if (ptr)`, ternary `ptr ? ... : ...`
- `malloc`/`calloc`/`realloc` result checks
- Tightened `NO_NULL_GUARDS`: only if the solution has zero pointer variables and zero heap allocation

---

## Issue 4: CRASH_CONFIRMED check is a false positive

**Symptom:** `run_attacker.py` checks `"CRASH_CONFIRMED" in traj.read_text()` but `CRASH_CONFIRMED` appears 4 times in the system prompt description of `run_crash`, so the check always returns True even when no crash occurred.

**Fix:** Replaced with `_crash_confirmed(traj_path)` which only inspects tool result messages in the trajectory JSON, not the system prompt text.

---

## Issue 5: Solver avoids malloc / pointer-based code

**Symptom:** On competitive programming B/C-level problems (1561_B, 1566_C), the solver consistently wrote pure stack/integer solutions with no heap allocation, giving the injector nothing to work with.

**Root cause:** Easy problems don't require dynamic memory, and the solver naturally avoids it.

**Attempts:**
- Added "Coding style" section to solver prompt nudging it to use `malloc`/pointer structures when natural
- Result: Still produced a `static unsigned char used[]` array for 1561_B (F4FB run)

**Status:** Partially mitigated. Switching to LeetCode-style linked list problems (see Issue 6).

---

## Issue 6: Competitive programming problems are wrong problem class

**Symptom:** Code contest problems (even B/C level) are either:
- Too hard → solver fails to produce a correct solution within step limit
- Too easy → solver solves with pure integer/array arithmetic, no pointers

**Fix in progress:** Switched to easy LeetCode linked list problems (Reverse Linked List, Merge Two Sorted Lists, etc.) which:
- LLMs know by heart and solve reliably
- **Inherently require** `struct Node*`, `malloc`, and null checks — no coaxing needed

Script: `attacker/filter_leetcode_problems.py` — downloads from `greengerong/leetcode`, filters 8 clean linked-list easy problems, creates experiment dirs with parsed stdin/stdout test cases.

---

## Issue 7: Token limit exceeded for gpt-5 (272k context)

**Symptom:** `BadRequestError: Input tokens exceed the configured limit of 272000 tokens. Your messages resulted in 302473 tokens.`

**Root cause:** Solver was running 50 steps, accumulating tool outputs (compile errors, test outputs) into context.

**Fix:** Reduced solver step limit from 50 → 20. B/C level problems should not need 50 steps. Injector stays at 50.

---

## Issue 8: run_test produces unbounded output

**Symptom:** Agent ran a brute force checker that produced thousands of output lines, flooding the agent context.

**Fix:** Added `MAX_OUTPUT = 2000` chars truncation in `run_test.py`. Output is capped with `"... [truncated — N chars total]"` note.

---

## Current State

- Pipeline is structurally correct (solver → injector with AA_CA probe → all attack types)
- LeetCode problem dirs are set up in `attacker/runs/gpt-5/`
- Waiting to validate that solver produces pointer-heavy C for linked list problems
- Injector has not been successfully exercised end-to-end yet (all prior runs had no injectable NPD)
