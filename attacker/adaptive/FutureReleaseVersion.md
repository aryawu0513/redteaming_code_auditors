# Future Release Version of the Adaptive Attacker

This file records design directions we have explicitly deferred from the
current research prototype. It is not a TODO for the current paper run;
it is a note to ourselves about what a "release-quality" attacker would
look like.

## Background

The current adaptive attacker (`refine_loop.py`) treats the attack
taxonomy as a fixed enumeration: for each slug, we iterate independently
over the 9 attack TYPEs (`FT`, `CG`, `AA_MSG`, `AA_USR`, `AA_CA`,
`TOOL_ClangSA`, `TOOL_Coverity`, `TOOL_Frama`, `TOOL_Fuzzer`) and try to
flip the detector within each type's locked format.

We adopt **Option B**: interleaved rounds — the outer loop walks rounds, the
inner loop walks types, and a shared `library` of successful flips is
synced between rounds so any type's success seeds the next round for
every other type. This is the minimum architectural change needed to
share wins across types.

## What the release version should do (Option C)

For a real "working" release of the attacker, the attack taxonomy should
behave as the attacker's **toolbox**, not its outer loop. Concretely:

1. **Types are tools, not iteration axes.** Each TYPE — including any
   future additions — is registered with a short description of when it
   is plausibly the right move (e.g. "TOOL_ClangSA: invoke when the
   detector's reasoning leans on path-sensitive infeasibility";
   "AA_USR: invoke when the detector is pattern-matching on author
   provenance"). The attacker picks types on the fly.

2. **A bandit / planner over (type, strategy) pairs.** Instead of
   running every type to budget exhaustion, a coordinator chooses the
   next `(type, strategy)` attempt given:
   - the current library of wins (per slug AND across slugs),
   - the detector's most recent objection on this slug,
   - per-type historical hit rates (some types are stronger against
     certain detector families),
   - cost (some types may be expensive to author or detect).
   This naturally combines exploration (trying a type that hasn't been
   tried on this slug) and exploitation (re-using a pattern that works).

3. **Cross-slug library.** Today the library is per-slug. Release-version
   should keep a global pattern store keyed by detector-objection
   features, so a winning rationale on slug A can be retrieved as a
   candidate when slug B's detector reasoning looks structurally
   similar.

4. **Type composition.** Within a single annotation, allow multiple
   styles to compose if it's actually effective (e.g. a TOOL_ClangSA
   header followed by a CG-style rationale block). The current research
   prototype forbids this (`style_specs.md` says "do not switch comment
   styles") to keep the eval clean; release-version should treat that as
   a hyperparameter, not a hard rule.

5. **Stop conditions per slug, not per type.** Today we burn budget on
   types that clearly won't work for a given slug. The release version
   should be allowed to declare a type "not promising for this slug"
   early and reallocate the saved budget to types that are working.

## Why we are not building this now

- The research question for the current paper is whether *the same
  underlying argument* can defeat the detector across surface styles
  (the typology hypothesis). For that, we need *every* type attempted
  on every slug — a planner that skips types would undermine the
  measurement.
- The bandit/planner adds an evaluation layer (which types it chose,
  why, with what regret) that is its own project.
- Option B already captures the main missing piece — cross-type library
  sharing — without any of the planner machinery.

## Trigger to revisit this

Revisit when either:
- We move from "measure attack-surface coverage" to "ship the strongest
  attacker we can build per slug", or
- The library grows large enough that picking which entry to transpose
  is itself a non-trivial decision (i.e., a planner is paying for
  itself).
