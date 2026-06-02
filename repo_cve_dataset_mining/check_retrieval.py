#!/usr/bin/env python3
"""
Check whether VulnLLM-R's agent actually uses [RETRIEVE] in practice.
Runs one candidate directly (not via HTTP) with verbose=True so we
can see retrieval events and rounds_used.
"""
import json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "VulnLLM-R"))
sys.path.insert(0, str(ROOT / "VulnLLM-R/vulscan/model_zoo/src"))

from agent_scaffold.scan import scan_project, make_vllm_fns  # noqa

rows = {(r["cve_id"], r["func_name"]): r
        for r in (json.loads(l) for l in
                  (ROOT / "repo_cve_dataset_mining/f3_relaxed_dedup.jsonl")
                  .read_text().splitlines())}

# dictCreate: NPD is through _dictInit which is defined in the same file
rec = rows[("CVE-2020-7105", "dictCreate")]
fc = rec.get("_fixed_code", "")
vc = rec.get("vulnerable_code", "")
ff = rec.get("full_file", "")
buggy = ff.replace(fc.strip(), vc.strip(), 1) if fc and fc.strip() in ff else ff

print("Loading VulnLLM-R-7B …")
model_fn, model_fn_diverse = make_vllm_fns("UCSB-SURFI/VulnLLM-R-7B", max_tokens=4096)

with tempfile.TemporaryDirectory() as tmpdir:
    (Path(tmpdir) / "dict.c").write_text(buggy)

    results = scan_project(
        repo_dir=tmpdir,
        language="c",
        model_fn=model_fn,
        n_paths=3,
        max_rounds=3,
        policy_runs=4,
        model_fn_diverse=model_fn_diverse,
        target_functions=["dictCreate"],
        cwe_hints=["CWE-476"],
        verbose=True,   # <-- shows RETRIEVE events
    )

r = results[0]
print(f"\n=== Result ===")
print(f"judge:       {r['judge']}")
print(f"cwe_type:    {r['cwe_type']}")
print(f"rounds_used: {r['rounds_used']}")
print(f"\nExploratory runs:")
for ex in r.get("exploratory_results", []):
    print(f"  run {ex['run']}: judge={ex['judge']} cwe={ex['cwe_type']} rounds={ex['rounds_used']}")
print(f"\nFinal runs:")
for fr in r.get("final_results", []):
    print(f"  cwe={fr['cwe']}: judge={fr['judge']} rounds={fr['rounds_used']}")
    if fr.get("output"):
        # Look for RETRIEVE in the output
        if "[RETRIEVE" in fr["output"]:
            print(f"  *** MODEL USED RETRIEVE ***")
            import re
            for m in re.finditer(r"\[RETRIEVE:\s*(\w+)\s*\]", fr["output"]):
                print(f"      requested: {m.group(1)}")
