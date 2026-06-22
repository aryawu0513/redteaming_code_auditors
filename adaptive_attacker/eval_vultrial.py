"""
eval_vultrial.py — Run VulTrial detection over existing attack records.

Mirrors the output layout of vulnllmr_full / openvul_full:
  results/{system}/repository_{slug}/
    baseline_gate_fromscratch_v1.json
    adaptive_{TYPE}_fromscratch_v1/round_{N}.json

Resume-safe: skips output files that already exist.
Parallelism: ThreadPoolExecutor over (slug, type, round) jobs.
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "adaptive_attacker"))
sys.path.insert(0, str(REPO_ROOT))

from refine_loop_fromscratch import insert_annotation

ATTACK_TYPES = [
    "COT", "FT", "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer",
]
ROUNDS = list(range(5))


def build_jobs(
    slugs: list[str],
    baseline_dir: Path,
    attack_dir: Path,
    out_root: Path,
) -> list[dict]:
    jobs = []
    for slug in slugs:
        bdir   = baseline_dir / f"repository_{slug}"
        bfiles = list(bdir.glob("*_CLEAN.json")) if bdir.exists() else []
        if not bfiles:
            continue
        baseline_record = json.loads(bfiles[0].read_text())[0]
        bare_tf = baseline_record.get("target_function", "")
        out_slug = out_root / f"repository_{slug}"

        # Baseline
        jobs.append({
            "slug":        slug,
            "variant_key": "CLEAN",
            "record":      baseline_record,
            "out_file":    out_slug / "baseline_gate_fromscratch_v1.json",
            "meta":        {},
        })

        # Attacks
        adir = attack_dir / f"repository_{slug}"
        if not adir.exists():
            continue
        for atype in ATTACK_TYPES:
            type_dir = adir / f"adaptive_{atype}_fromscratch_v1"
            for rnd in ROUNDS:
                rfile = type_dir / f"round_{rnd}.json"
                if not rfile.exists():
                    continue
                rdata = json.loads(rfile.read_text())
                if isinstance(rdata, list):
                    rdata = rdata[0]

                annotation_text = rdata.get("annotation_text", "")
                insert_before   = rdata.get("insert_before", "")
                if not annotation_text or not insert_before:
                    continue
                try:
                    annotated_tf = insert_annotation(bare_tf, annotation_text, insert_before)
                except ValueError:
                    continue

                jobs.append({
                    "slug":        slug,
                    "variant_key": f"{atype}_r{rnd}",
                    "record":      {
                        **baseline_record,
                        "target_function": annotated_tf,
                        "slug":            slug,
                        "variant":         f"{atype}_r{rnd}",
                    },
                    "out_file": out_slug / f"adaptive_{atype}_fromscratch_v1" / f"round_{rnd}.json",
                    "meta": {
                        "round":           rnd,
                        "annotation_text": annotation_text,
                        "insert_before":   insert_before,
                    },
                })
    return jobs


def _run_job(job: dict, det) -> dict:
    slug  = job["slug"]
    vkey  = job["variant_key"]
    t0    = time.time()
    try:
        result  = det.detect(job["record"])
        elapsed = time.time() - t0
        verdict   = result["verdict"]
        reasoning = result.get("reasoning", "")
    except Exception as exc:
        return {"slug": slug, "variant_key": vkey, "verdict": "error",
                "elapsed": round(time.time() - t0, 1), "error": str(exc)}

    votes = {"has_vul": 1, "no_vul": 0} if verdict == "vulnerable" else {"has_vul": 0, "no_vul": 1}
    out_file = job["out_file"]
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if vkey == "CLEAN":
        payload = {"slug": slug, "verdict": verdict, "votes": votes, "reasoning": reasoning}
    else:
        meta = job["meta"]
        payload = {
            "round":               meta["round"],
            "phase":               "fromscratch_bootstrap",
            "annotation_text":     meta["annotation_text"],
            "insert_before":       meta["insert_before"],
            "detector_verdict":    verdict,
            "detector_reasoning":  reasoning,
            "votes":               votes,
        }

    out_file.write_text(json.dumps(payload, indent=2))
    return {"slug": slug, "variant_key": vkey, "verdict": verdict,
            "elapsed": round(elapsed, 1), "error": None}


def run(
    slugs: list[str],
    baseline_dir: Path,
    attack_dir: Path,
    out_root: Path,
    model: str = "gpt-4o",
    mode: str  = "npd",
    workers: int = 8,
    dry_run: bool = False,
) -> None:
    from detector_vultrial import VulTrialDetector

    jobs    = build_jobs(slugs, baseline_dir, attack_dir, out_root)
    pending = [j for j in jobs if not j["out_file"].exists()]
    done    = len(jobs) - len(pending)

    print(f"Jobs: {len(jobs)}  |  done: {done}  |  pending: {len(pending)}")
    print(f"Output: {out_root}")

    if dry_run or not pending:
        if not pending:
            print("Nothing to do.")
        return

    det     = VulTrialDetector(model=model, mode=mode)
    t_start = time.time()
    completed = errors = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_run_job, j, det): j for j in pending}
        for fut in as_completed(futures):
            res = fut.result()
            completed += 1
            if res["error"]:
                errors += 1
            status = "ERR" if res["error"] else res["verdict"][:4].upper()
            print(
                f"[{completed:4d}/{len(pending)}]"
                f"  {res['slug']:20s}  {res['variant_key']:25s}"
                f"  {status}  ({res['elapsed']:.1f}s)"
                f"  total={time.time()-t_start:.0f}s"
            )

    print(f"\nDone. {completed} runs, {errors} errors.")
