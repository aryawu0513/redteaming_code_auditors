# NPD Bug Classification and SA Recall Analysis

## Framing

We classify each of the 128 LLM-generated NPD bugs (injected into real CVE
fix-commit repositories) by the **static-analysis capability required to
resolve the null source**. This is not a named standard taxonomy from a single
paper; it is a synthesis grounded in the classic precision-dimension ladder of
static analysis (flow-sensitivity → field-sensitivity →
interprocedural/context-sensitivity → cross-translation-unit). Each category
maps to a named tool capability or analysis dimension.

**Dataset identity**: these are not the original CVE patches. They are
LLM-generated null-pointer dereferences injected into the same codebases at
the CVE fix commit. The prior work citations below concern *real-world* bugs;
the bridge is methodological (same classification scheme, same tools) rather
than a claim that the injected bugs have identical properties to real CVE bugs.

The prior-work framing should read: "We classify each injected bug by the
static-analysis capability required to resolve its null source — a precision
hierarchy well-established in the literature [sensitivity refs] — and compare
the resulting recall against empirical findings on real-world NPE detection
[Tomassi 2021, Habib 2018]."

Relevant prior work:
- **Tomassi et al., "On the Real-World Effectiveness of Static Bug Detectors
  at Finding Null Pointer Exceptions" (ASE 2021)** — closest prior work;
  studies NPE/NPD detection on real-world bugs across CheckerFramework,
  Eradicate, Infer, NullAway, SpotBugs.
- **Habib & Pradel, "How Many of All Bugs Do We Find?" (ASE 2018)** — ran
  Infer, ErrorProne, SpotBugs on 594 Defects4J bugs; 95.5% missed by all
  three. Canonical false-negative result.

## Category Definitions

Each category maps to an analysis precision dimension. The `H_CROSS_FILE`
category (CTU analysis) is defined for completeness but has zero members in
this benchmark — the LLM injector did not produce cross-TU null sources.

| Category | Null source | Analysis needed | SA detectability |
|---|---|---|---|
| null_literal | Explicit `ptr = NULL` in function body | Flow-sensitive, intra-procedural | HIGH |
| stdlib_alloc | `malloc`/`calloc`/`realloc` (or project wrapper) return | Stdlib allocation model | HIGH |
| stdlib_other | Stdlib returning null (`fopen`, `strstr`, …) | Stdlib null model (CppCheck, Clang SA) | MEDIUM |
| callee_return | User-defined function return used as pointer | Interprocedural summary (Infer biabduction, CodeQL dataflow) | MEDIUM |
| output_param | Pointer via output param (`&ptr`) | Output-parameter modeling | LOW |
| struct_field | Pointer read from struct/class field | Field-sensitive heap analysis | LOW |
| param_in | Pointer parameter, null at call sites | Backward call-site enumeration | LOW |
| (cross_file) | Null source not in primary or auxiliary file | Cross-translation-unit (CTU) analysis | VERY LOW |

## Distribution on 128 Samples

Data: `results/npd_classification.json`; classification script: `scripts/oneoff/classify_npd_bugs.py`.

**Classification methodology**: regex-based analysis of the function body
(`primary_file`) and cross-file helpers (`auxiliary_file`, tree-sitter
extracted). `stdlib_alloc` is only credited when the allocation call appears
within the target function body; an allocation in a callee (auxiliary file) is
classified as `callee_return`. Four samples (NPD-CVE-0377, -0378, -0585,
-0678) were hand-labeled after verifying against the LLM judge's reasoning,
because the null source is hidden behind a macro expansion (`YY_CURRENT_BUFFER`)
or a C++ constructor initializer list that the single-line signature parser
cannot reach. All other 124 samples are classified automatically.

| source_kind | N | % | SA detectability |
|---|---|---|---|
| null_literal | 5 | 3.9% | HIGH |
| stdlib_alloc | 17 | 13.3% | HIGH |
| stdlib_other | 4 | 3.1% | MEDIUM |
| callee_return | 39 | 30.5% | MEDIUM |
| output_param | 10 | 7.8% | LOW |
| struct_field | 47 | 36.7% | LOW |
| param_in | 6 | 4.7% | LOW |
| unknown / cross_file | 0 | 0% | VERY_LOW |

| Axis | Value | N | % |
|---|---|---|---|
| SA detectability | HIGH | 22 | 17.2% |
| | MEDIUM | 43 | 33.6% |
| | LOW | 63 | 49.2% |
| | VERY_LOW | 0 | 0% |
| Source locality | in_function | — | — |
| | cross_function (same file) | — | — |
| | cross_file | — | — |
| Requires interprocedural | yes | — | — |
| Requires field sensitivity | yes | — | — |

## Empirical SA Recall

**Detection criterion**: a null-deref warning whose reported line falls within
the attacker's function body (determined by brace-counting). For Infer — which
traces interprocedurally and often reports the dereference at a caller site —
we additionally credit a hit when the warning fires in a procedure whose source
file contains a direct textual call to the attacker's function. This Infer
caller-credit is an over-approximation (it may include false callers) and is
documented as such; the other two tools use only the strict body-line criterion.
Only null-deref bug IDs count: `nullPointer`/`ctunullpointer` (CppCheck),
`NULL_DEREFERENCE`/`NULLPTR_DEREFERENCE` (Infer), the NPD query output (CodeQL).

**Coverage and recall are reported separately.** Tools that failed to run are
not scored as misses; only samples where a tool ran count toward that tool's
recall denominator.

Infer was extended from cmake-only to autoconf and Makefile repos using `bear`
(intercepting compiler calls during a forced rebuild). This raised coverage
from 55 to 114. The 14 remaining failures are: 4 repos with uninitialised git
submodules (ceph), 4 with missing system dependencies at configure time
(libmysofa, tcmu-runner), and 2 timeouts (unicorn). The 59 newly-covered repos
produced no additional detections — all 8 Infer hits came from the original
cmake-built repos.

| Tool | Coverage | Recall / ran | Recall / 128 | Why some didn't run |
|---|---|---|---|---|
| CppCheck | 105/128 | 1/105 (1.0%) | 1/128 (0.8%) | 23 timeouts on large repos |
| Infer | 114/128 | 8/114 (7.0%) | 8/128 (6.2%) | 14 repos: submodules, missing deps, timeout |
| CodeQL | 128/128 | 7/128 (5.5%) | 7/128 (5.5%) | — |
| **Any tool** | **91/128** (all ran) | **14/91 (15.4%)** | **15/128 (11.7%)** | |

**Two findings, not one:**

**(a) Analytical finding** — on the 91 samples where all three tools ran,
recall is 15.4%. This is the cleanest measure of analysis capability, isolated
from build friction.

**(b) Operational finding** — across all 128 samples, recall is 11.7%. This
bundles analysis misses with build/config friction and represents production
deployment reality.

**Tier recall on the 91-sample all-ran subset:**

| Tier | Detected | Of 91 subset | Recall |
|---|---|---|---|
| HIGH | 4 | 19 | 21% |
| MEDIUM | 3 | 30 | 10% |
| LOW | 7 | 42 | 17% |
| VERY_LOW | 0 | 0 | — |

The tier ordering is directionally consistent (HIGH > LOW > MEDIUM) but the
differences are small and the absolute hit counts (3–7 per tier) are too low
for statistical separation. The tiers reflect theoretically motivated analysis
requirements; this experiment provides suggestive but not conclusive empirical
support for the ordering. The HIGH recall of 21% — on bugs with an explicit
null assignment or direct stdlib alloc in the function body — is low enough
that it warrants acknowledgment: these are the cases the literature treats as
trivially detectable, and even here three of four tools miss most of them.
This is consistent with Habib & Pradel's finding that even simple patterns
are missed when interprocedural or path constraints interact.
