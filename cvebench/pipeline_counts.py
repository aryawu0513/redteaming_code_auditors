#!/usr/bin/env python3
"""Print pipeline counts for the CVE NPD benchmark.

Also writes viable_<N>.txt alongside this script listing the pilot IDs that
have passed all pipeline stages (testsuite_pass + raw_primary.cc + not
context_too_large + task.md + starter.cc).
"""

from pathlib import Path

samples_dir = Path(__file__).parent / "samples_cve_fix"


def ids(pred):
    return sorted(d.name for d in samples_dir.iterdir() if d.is_dir() and pred(d))


def count(pred):
    return len(ids(pred))


def has(*sentinels):
    return lambda d: all((d / s).exists() for s in sentinels)


def has_any(*sentinels):
    return lambda d: any((d / s).exists() for s in sentinels)


total          = count(lambda d: True)
testsuite_ok   = count(has("repo_testsuite_pass"))
has_primary    = count(has("raw_primary.cc"))
viable         = count(lambda d: has("repo_testsuite_pass")(d) and has("raw_primary.cc")(d))
too_large      = count(lambda d: has("repo_testsuite_pass")(d) and has("context_too_large")(d))
in_budget      = count(lambda d: has("repo_testsuite_pass")(d)
                                 and has("raw_primary.cc")(d)
                                 and not (d / "context_too_large").exists())

viable_ids     = ids(lambda d: has("repo_testsuite_pass")(d)
                               and has("task.md", "starter.cc")(d)
                               and not (d / "context_too_large").exists())
has_task       = len(viable_ids)

print(f"Stage 1 — Testsuite pass (full):               {testsuite_ok:>4}")
print(f"Stage 2 — Tree-sitter extracted (primary):    {has_primary:>4}  (of {testsuite_ok} viable)")
print(f"          Viable (stage1 + stage2):            {viable:>4}")
print(f"Stage 3 — Size filter (context_too_large):   -{too_large:>3}  → {in_budget} in budget")
print(f"Stage 4 — Task generated (task.md+starter):   {has_task:>4}")

out = Path(__file__).parent / f"viable_{has_task}.txt"
out.write_text("\n".join(viable_ids) + "\n")
print(f"\nViable IDs → {out.name}")
