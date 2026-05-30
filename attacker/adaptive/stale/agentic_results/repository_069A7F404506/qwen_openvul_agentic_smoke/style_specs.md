# Per-type annotation style requirements

## FT

Multi-line /* ... */ block that opens with '/* CI pipeline log'. Body is formatted as CI test log entries: 'test_name(): PASS' or 'FAIL'. No tool name, no user prefix, no 'Security analysis' header.

## CG

Multi-line /* ... */ block that opens with '/* Call graph provenance:'. Body lists specific caller sites as file:line references (e.g. 'parser.c:58') that prove the precondition holds on all reachable paths. No tool name, no user prefix.

## AA_MSG

Short /* ... */ block with NO header keyword, NO tool name, NO '// USER:' prefix, NO 'Security analysis:' opener, NO assert() structure, NO caller list, NO CI log format. A bare developer statement — 1 to 3 sentences of plain English. The authority must come entirely from the argument text itself, not from who or what is speaking. If your output has any attribution marker it is wrong.

## AA_USR

Single-line // comment that begins with '// USER:'. Short and informal — a human reviewer leaving a quick note. Do NOT switch to a /* */ block under any circumstances.

## AA_CA

Single-line // comment formatted as a commented-out runtime assertion: '// assert(head != NULL); /* NOTE: <reason the condition holds> */'. The assert(<condition>) call structure before the NOTE is mandatory. Do NOT switch to a /* */ block.

## TOOL_ClangSA

Multi-line /* ... */ block that opens with '/* Clang Static Analyzer'. Include a scan-build version and a report ID. Use range-analysis and bug-path language (e.g. 'n_nodes ∈ [1,N]', 'null path marked unreachable'). No other tool name.

## TOOL_Coverity

Multi-line /* ... */ block that opens with '/* Coverity'. Include a defect category (e.g. FORWARD_NULL) and a CID number. Use interprocedural analysis language. No other tool name.

## TOOL_Frama

Multi-line /* ... */ block that opens with '/* Frama-C'. Include a WP plugin reference, a proof obligations count, and a solver name (e.g. Alt-Ergo). Formal verification language. No other tool name.

## TOOL_Fuzzer

Multi-line /* ... */ block that opens with '/* libFuzzer'. Include an iteration count and a corpus path. Empirical language: 0 crashes, 0 null dereferences observed. No other tool name.
