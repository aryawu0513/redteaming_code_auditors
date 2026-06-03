#!/usr/bin/env python3
"""
Test VulnLLM-R on filter-3 candidates.

Usage:
    python test_vulnllmr.py [input.jsonl] [--candidates-dir candidates/]

- Streams results to <input>.results.jsonl as they arrive.
- Writes candidate.json immediately on a hit.
- Skips entries where buggy-file reconstruction fails.
- No resume: always runs all entries fresh.
"""
import argparse
import json
import sys
from pathlib import Path

import requests

URL = "http://localhost:8008"


def make_buggy(rec):
    fc = rec.get("_fixed_code", "")
    vc = rec.get("vulnerable_code", "")
    ff = rec.get("full_file", "")
    if fc and fc.strip() in ff:
        return ff.replace(fc.strip(), vc.strip(), 1)
    return None   # reconstruction failed — skip


def detect(code: str, func_name: str, file_path: str) -> dict:
    body = {
        "code": code,
        "context": "",
        "target_function": code,
        "function_name": func_name,
        "file_name": Path(file_path).name,
    }
    r = requests.post(f"{URL}/detect", json=body, timeout=300)
    r.raise_for_status()
    return r.json()


def write_candidate(rec: dict, buggy: str, candidates_dir: Path):
    candidate = {k: v for k, v in rec.items() if not k.startswith("_")}
    candidate["full_file"] = buggy
    fp   = rec.get("file_path", "")
    fn   = rec.get("func_name", "")
    cve  = rec.get("cve_id", "")
    slug = f"{cve}_{Path(fp).stem}_{fn}"[:80].replace("/", "_").replace(" ", "_")
    out  = candidates_dir / f"{slug}.json"
    out.write_text(json.dumps(candidate, indent=2))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?",
                    default="repo_cve_dataset_mining/f3_dedup.jsonl")
    ap.add_argument("--candidates-dir", default="repo_cve_dataset_mining/candidates")
    args = ap.parse_args()

    in_path  = Path(args.input)
    out_path = in_path.with_suffix(".results.jsonl")
    cand_dir = Path(args.candidates_dir)
    cand_dir.mkdir(parents=True, exist_ok=True)

    rows = [json.loads(l) for l in in_path.read_text().splitlines() if l.strip()]
    print(f"{len(rows)} candidates from {in_path}")
    print(f"Results → {out_path}  (overwritten each run)")
    print(f"Hits    → {cand_dir}/\n")

    try:
        requests.get(f"{URL}/health", timeout=5).raise_for_status()
    except Exception as e:
        print(f"ERROR: VulnLLM-R not reachable at {URL}: {e}")
        sys.exit(1)

    hits = misses = errors = skipped = 0

    with out_path.open("w") as fout:   # overwrite — no resume
        for i, rec in enumerate(rows):
            fn  = rec.get("func_name", "")
            fp  = rec.get("file_path", "")
            cve = rec.get("cve_id", "")
            tag = f"[{i+1}/{len(rows)}]"

            buggy = make_buggy(rec)
            if buggy is None:
                print(f"{tag} SKIP (reconstruction failed): {cve} {fn}")
                skipped += 1
                fout.write(json.dumps({
                    "cve_id": cve, "func_name": fn, "file_path": fp,
                    "verdict": "skip", "reasoning": "fixed_code not found in full_file",
                }) + "\n")
                fout.flush()
                continue

            print(f"{tag} {cve:20} {fn:35} ...", end=" ", flush=True)

            verdict = reasoning = ""
            try:
                out    = detect(buggy, fn, fp)
                verdict   = out.get("verdict", "error")
                reasoning = out.get("reasoning", "")
            except Exception as e:
                verdict   = "error"
                reasoning = str(e)

            symbol = "✓ VULN" if verdict == "vulnerable" else \
                     ("✗ safe" if verdict == "safe" else "! error")
            print(symbol)

            fout.write(json.dumps({
                "cve_id": cve, "func_name": fn, "file_path": fp,
                "verdict": verdict, "reasoning": reasoning,
            }) + "\n")
            fout.flush()

            if verdict == "vulnerable":
                hits += 1
                out_f = write_candidate(rec, buggy, cand_dir)
                print(f"          → {out_f.name}")
            elif verdict == "safe":
                misses += 1
            else:
                errors += 1

    print(f"\n{'='*60}")
    print(f"hits={hits}  safe={misses}  errors={errors}  skipped={skipped}")
    print(f"Results → {out_path}")


if __name__ == "__main__":
    main()
