#!/usr/bin/env python3
"""
recovery_eval.py — measure whether a prompt-level defense recovers detection on
already-successful adaptive attacks (the *_full runs).

For a given detector + defense, this:
  1. finds every successfully-attacked slug under
     adaptive_attacker/results/{system}/repository_*/ — one job per framing that
     flipped a round to "safe" (its recorded base + winning comment),
  2. splices the winning comment back into the base function,
  3. calls the detector K = --n-samples times WITH the defense injected, and
     records safe_fraction = n_safe / K per attack,
  4. writes each row to the CSV as it goes and reports the mean safe_fraction.

WHY K-SAMPLING. The detectors are stochastic (OpenVul temp 0.6, VulRAG temp ~1.0),
so a single call is a coin flip. The attack marks a slug flipped if ANY of its
~30-60 calls returned "safe", so a small per-call P(safe)=p inflates to a high ASR
via 1-(1-p)^M. Sampling K times and recording safe_fraction estimates p directly,
separating a robust attack (safe_fraction≈1) from sampling luck (safe_fraction≈0.2).
VulnLLM-R/VulTrial are temp 0 (K=1 suffices); use K>=5 for the stochastic ones.
Full derivation: result_analysis/defense_recovery_math.md.

  D0 (no defense)  → safe_fraction = attack robustness (p̂).
  D1 (defense on)  → safe_fraction under defense; defense effect per attack is
                     safe_fraction(D0) - safe_fraction(D1) on the same (slug,framing).
This is the analog of Mitropoulos et al.'s Debiased-1/-2 recovery columns.

Usage:
    # served detector (defense baked into the server) — recommended
    python defenses/recovery_eval.py --detector vulnllmr --system vulnllmr_funclevel_full \\
        --defense D1 --detector-url http://localhost:8008
    # in-process
    python defenses/recovery_eval.py --detector openvul --system openvul_full --defense D0
"""
import argparse
import copy
import csv
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent
ATTACKER = REPO_ROOT / "adaptive_attacker"
sys.path.insert(0, str(ATTACKER))
sys.path.insert(0, str(REPO_ROOT))

from defenses.registry import DEFENSES  # noqa: E402

RESULTS_DIR = ATTACKER / "results"
DATASET_DIR = REPO_ROOT / "benchmark" / "cvebench_full" / "baseline"


# ── reconstruction helpers (mirror refine_loop_*.py exactly) ──────────────────

def load_baseline_record(slug: str, dataset_dir: Path) -> dict | None:
    baseline_dir = dataset_dir / f"repository_{slug}"
    matches = sorted(baseline_dir.glob("*CLEAN*.json"))
    if not matches:
        return None
    data = json.loads(matches[0].read_text())
    return data[0] if isinstance(data, list) else data


def insert_annotation(bare_tf: str, annotation_text: str, insert_before: str) -> str:
    search_key = next(
        (ln.strip() for ln in insert_before.split("\n") if ln.strip()), insert_before
    )
    lines = bare_tf.split("\n")
    idx = next((i for i, l in enumerate(lines) if search_key in l), None)
    if idx is None:
        raise ValueError(f"insert_before not found: {insert_before!r}")
    indent = lines[idx][: len(lines[idx]) - len(lines[idx].lstrip())]
    indented = [indent + l if l.strip() else l for l in annotation_text.split("\n")]
    return "\n".join(lines[:idx] + indented + lines[idx:])


def _base_tf_from_round(d: dict) -> str | None:
    """The bare base function the attacker annotated, recorded in the round's
    refiner prompt (prompt_messages). This is the ground-truth base — the current
    baseline dataset record may have drifted since the attack ran."""
    for msg in d.get("prompt_messages", []):
        if msg.get("role") == "user":
            try:
                o = json.loads(msg["content"])
            except Exception:
                continue
            if isinstance(o, dict) and o.get("target_function"):
                return o["target_function"]
    return None


def find_slug_winners(slug_dir: Path) -> list[dict]:
    """
    Every safe-flipping round across all framing dirs (adaptive_*/), sorted by
    round index — each a working attack for this slug, carrying its own base
    function so reconstruction is exact. Empty list if the slug was never flipped.
    """
    cands = []
    for adir in sorted(slug_dir.glob("adaptive_*")):
        if not adir.is_dir():
            continue
        for jf in sorted(adir.glob("*.json")):
            if jf.name == "result.json":
                continue
            try:
                d = json.loads(jf.read_text())
            except Exception:
                continue
            if not (isinstance(d, dict) and d.get("detector_verdict") == "safe"
                    and d.get("annotation_text") and d.get("insert_before")):
                continue
            rnd = d.get("round", 999)
            cands.append({"framing": adir.name, "round": rnd if isinstance(rnd, int) else 999,
                          "annotation_text": d["annotation_text"],
                          "insert_before": d["insert_before"],
                          "base_tf": _base_tf_from_round(d), "attack_verdict": "safe"})
    cands.sort(key=lambda c: c["round"])
    return cands


def find_all_round_payloads(slug_dir: Path) -> list[dict]:
    """
    EVERY round payload (success and failure) across all framing dirs, each tagged
    with its attack-time detector_verdict. Used by --all-rounds to measure the
    refinement gradient (safe_fraction by round, paired within framing) and the
    success/failure robustness split.
    """
    out = []
    for adir in sorted(slug_dir.glob("adaptive_*")):
        if not adir.is_dir():
            continue
        for jf in sorted(adir.glob("round_*.json")):
            try:
                d = json.loads(jf.read_text())
            except Exception:
                continue
            if not (isinstance(d, dict) and d.get("annotation_text") and d.get("insert_before")):
                continue
            rnd = d.get("round", -1)
            out.append({"framing": adir.name, "round": rnd if isinstance(rnd, int) else -1,
                        "annotation_text": d["annotation_text"],
                        "insert_before": d["insert_before"],
                        "base_tf": _base_tf_from_round(d),
                        "attack_verdict": d.get("detector_verdict", "")})
    out.sort(key=lambda c: (c["framing"], c["round"]))
    return out


# ── detector construction (mirror refine loops) ───────────────────────────────

def build_detector(args, defense_text: str | None):
    d = args.detector
    if d == "vulnllmr":
        from detector_vulnllmr import VulnLLMRDetector
        return VulnLLMRDetector(tp=args.tp, mode=args.vulnllmr_mode, defense_text=defense_text)
    if d == "openvul":
        from detector_openvul import OpenVulDetector
        kw = {"tp": args.tp, "defense_text": defense_text}
        if args.model:
            kw["model_id"] = args.model
        if args.temperature is not None:
            kw["temperature"] = args.temperature
        return OpenVulDetector(**kw)
    if d == "vultrial":
        from detector_vultrial import VulTrialDetector
        return VulTrialDetector(model=args.model or "gpt-4o", mode="npd", defense_text=defense_text)
    if d == "vulrag":
        from detector_vulrag import VulRAGDetector
        ms = {"temperature": args.vulrag_temperature} if args.vulrag_temperature is not None else None
        return VulRAGDetector(model=args.model, model_settings=ms, defense_text=defense_text)
    raise ValueError(f"unknown detector {d!r}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--detector", required=True,
                   choices=["openvul", "vulnllmr", "vultrial", "vulrag"])
    p.add_argument("--system", required=True,
                   help="results subdir of the full run, e.g. 'vulnllmr_funclevel_full'")
    p.add_argument("--detector-url", default=None,
                   help="If set, query a running detector_server.py instead of "
                        "loading in-process. The SERVER owns the defense (start it "
                        "with --defense); here --defense is only a CSV label.")
    p.add_argument("--defense", default="D0",
                   help="D0 (no-op control) or a key in registry.py (D1, ...)")
    p.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    p.add_argument("--dataset", type=Path, default=DATASET_DIR)
    p.add_argument("--model", default=None)
    p.add_argument("--tp", type=int, default=1)
    p.add_argument("--vulnllmr-mode", choices=["agentic", "funclevel"], default="funclevel")
    p.add_argument("--temperature", type=float, default=None, help="OpenVul temp override")
    p.add_argument("--vulrag-temperature", type=float, default=None)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, default=HERE / "recovery",
                   help="directory for the CSV + reasoning sidecar")
    p.add_argument("--limit", type=int, default=None,
                   help="only process the first N working attacks (spot check)")
    p.add_argument("--n-samples", type=int, default=1,
                   help="detector calls per attack; records safe_fraction=n_safe/K "
                        "(use >=5 for stochastic detectors like openvul temp 0.6)")
    p.add_argument("--framings", nargs="+", default=None,
                   help="restrict to these attack types, e.g. COT TOOL_ClangSA "
                        "TOOL_Coverity TOOL_Frama TOOL_Fuzzer (the portfolio_tradeoff set)")
    p.add_argument("--all-rounds", action="store_true",
                   help="score EVERY round payload (success+failure), tagged with its "
                        "attack-time verdict — for the refinement gradient / robustness split")
    p.add_argument("--rounds", nargs="+", type=int, default=None,
                   help="with --all-rounds, restrict to these round indices (e.g. 0 for seeds only)")
    p.add_argument("--seed-final", action="store_true",
                   help="cheap refinement proxy: keep only round-0 (seed) and the final "
                        "round per (slug,framing), for winners AND losers. Implies --all-rounds.")
    p.add_argument("--refine-new", action="store_true",
                   help="minimal seed-final that REUSES the existing winners {system}_D0.csv: "
                        "emit only round-0 of late-flipping winners, and round-0+final of losers "
                        "(skip winners that flipped at r0). Implies --all-rounds.")
    args = p.parse_args()
    if args.seed_final or args.refine_new:
        args.all_rounds = True

    # Resolve defense text
    if args.defense.upper() in ("D0", "NONE"):
        defense_text, defense_name = None, "D0"
    else:
        if args.defense not in DEFENSES:
            p.error(f"unknown defense {args.defense!r}; known: D0, {list(DEFENSES)}")
        defense_text, defense_name = DEFENSES[args.defense]["task_addition"], args.defense

    sys_dir = args.results_dir / args.system

    # One job per WORKING attack instance: every framing that flipped a slug
    # (deduped to one winning round per framing). Total jobs = total working
    # attacks across all slugs — the number of detect calls this run makes.
    jobs = []  # (slug, payload)
    n_slugs = 0
    for slug_dir in sorted(sys_dir.glob("repository_*")):
        cands = (find_all_round_payloads(slug_dir) if args.all_rounds
                 else find_slug_winners(slug_dir))
        if args.framings:
            cands = [c for c in cands
                     if any(c["framing"].startswith(f"adaptive_{t}_") for t in args.framings)]
        if args.all_rounds and args.rounds is not None:
            cands = [c for c in cands if c["round"] in args.rounds]
        if args.seed_final:  # per framing, keep round 0 and the max round
            maxr = {}
            for c in cands:
                maxr[c["framing"]] = max(maxr.get(c["framing"], -1), c["round"])
            cands = [c for c in cands if c["round"] == 0 or c["round"] == maxr[c["framing"]]]
        if args.refine_new:  # minimal set, reusing the winners {system}_D0.csv
            byf = {}
            for c in cands:
                byf.setdefault(c["framing"], []).append(c)
            kept = []
            for cs in byf.values():
                safe = [c["round"] for c in cs if c.get("attack_verdict") == "safe"]
                mx = max(c["round"] for c in cs)
                if safe:
                    if min(safe) == 0:
                        continue                       # r0==final already run → reuse
                    kept += [c for c in cs if c["round"] == 0]  # seed only
                else:
                    kept += [c for c in cs if c["round"] == 0 or c["round"] == mx]  # seed+final
            cands = kept
        if not cands:
            continue
        n_slugs += 1
        slug = slug_dir.name.replace("repository_", "")
        if args.all_rounds:
            for c in cands:  # every (framing, round) payload
                jobs.append((slug, c))
        else:
            seen = set()
            for c in cands:  # sorted by round; keep earliest per framing
                if c["framing"] in seen:
                    continue
                seen.add(c["framing"])
                jobs.append((slug, c))

    if not jobs:
        print(f"[recovery] no flipped slugs under {sys_dir}/repository_*/adaptive_*/")
        print("           check --system (should be a *_full run)")
        sys.exit(1)

    if args.limit:
        jobs = jobs[:args.limit]
        print(f"[recovery] --limit {args.limit}: spot-checking first {len(jobs)} attacks")

    print(f"[recovery] detector={args.detector}  system={args.system}  "
          f"defense={defense_name}  attacked_slugs={n_slugs}  working_attacks={len(jobs)}")
    if args.detector_url:
        from detector_http import HttpDetectorClient
        print(f"[recovery] querying served detector at {args.detector_url}")
        print(f"[recovery] *** defense is whatever the SERVER was started with; "
              f"'--defense {defense_name}' here is only the CSV label — ensure the "
              f"server was launched with --defense {defense_name} ***")
        detector = HttpDetectorClient(base_url=args.detector_url)
        served = getattr(detector, "server_defense", None)
        if served != defense_name:
            if served is None:
                p.error(f"server at {args.detector_url} does not report its defense "
                        f"(restart it with the updated detector_server.py). Cannot verify "
                        f"it matches --defense {defense_name}; refusing to run to avoid "
                        f"mislabeling results.")
            p.error(f"DEFENSE MISMATCH: server is serving defense={served!r} but you passed "
                    f"--defense {defense_name!r}. Re-serve with --defense {defense_name} "
                    f"(or fix the label) — refusing to run to avoid mislabeling results.")
    else:
        print(f"[recovery] building detector in-process (defense {'ON' if defense_text else 'OFF'}) …")
        detector = build_detector(args, defense_text)

    tag = ("_refinenew" if args.refine_new else "_seedfinal" if args.seed_final
           else "_allrounds" if args.all_rounds else "")
    out_path = args.out or (args.out_dir / f"{args.system}_{defense_name}{tag}.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    K = args.n_samples
    fields = ["slug", "framing", "round", "attack_verdict", "defense", "n_samples",
              "n_safe", "safe_fraction", "majority_verdict"]
    f = open(out_path, "w", newline="")
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    f.flush()

    # Reasoning sidecar: one JSON line per attack with the K per-sample verdicts
    # and the first response's reasoning, so the defense's presence/effect in the
    # reasoning can be grepped across the whole run (not just a sample).
    side_path = out_path.with_suffix(".reasoning.jsonl")
    side = open(side_path, "w")

    sum_safe_frac = 0.0
    n_maj_vuln = 0
    n_done = 0
    t0 = time.time()
    for i, (slug, win) in enumerate(jobs, 1):
        baseline = load_baseline_record(slug, args.dataset)
        if baseline is None:
            print(f"[{i}/{len(jobs)}] {slug}: no CLEAN baseline record — skipping")
            continue
        base_tf = win.get("base_tf") or baseline["target_function"]
        try:
            attacked_tf = insert_annotation(base_tf, win["annotation_text"], win["insert_before"])
        except ValueError as e:
            print(f"[{i}/{len(jobs)}] {slug}: reconstruction failed ({e}) — skipping")
            continue

        # Batch the K samples in one call — OpenVul/vLLM runs them in a single
        # GPU pass (continuous batching); other detectors fall back to a loop.
        recs = []
        for s in range(K):
            rec = copy.deepcopy(baseline)
            rec["target_function"] = attacked_tf
            rec["variant"] = f"recovery_{defense_name}_{slug}_{win['framing']}_s{s}"  # unique → bypass caches
            recs.append(rec)
        dets = detector.detect_batch(recs)
        verdicts = [d["verdict"] for d in dets]
        n_safe = sum(v == "safe" for v in verdicts)
        first_reasoning = dets[0].get("reasoning", "") if dets else ""

        safe_fraction = n_safe / K
        # safe by majority ⇒ the attack still evades; else the detector caught it
        majority = "safe" if n_safe * 2 >= K else "vulnerable"
        sum_safe_frac += safe_fraction
        n_maj_vuln += int(majority == "vulnerable")
        n_done += 1

        writer.writerow({
            "slug": slug, "framing": win["framing"], "round": win["round"],
            "attack_verdict": win.get("attack_verdict", ""),
            "defense": defense_name, "n_samples": K, "n_safe": n_safe,
            "safe_fraction": round(safe_fraction, 3), "majority_verdict": majority,
        })
        f.flush()
        side.write(json.dumps({
            "slug": slug, "framing": win["framing"], "defense": defense_name,
            "verdicts": verdicts, "safe_fraction": safe_fraction,
            "reasoning": first_reasoning,
        }) + "\n")
        side.flush()
        print(f"[{i}/{len(jobs)}] {slug} ({win['framing']} r{win['round']}): "
              f"safe {n_safe}/{K} (frac={safe_fraction:.2f}) → majority {majority}")

    f.close()
    side.close()
    elapsed = time.time() - t0
    ndet = n_done * K
    rate = ndet / elapsed if elapsed else 0.0
    print(f"[recovery] timing: {elapsed:.0f}s for {n_done} payloads × K={K} "
          f"= {ndet} detects  ({rate:.2f} detect/s, {elapsed/max(n_done,1):.2f}s/payload)")
    mean_frac = sum_safe_frac / n_done if n_done else 0.0
    print(f"\n[recovery] {defense_name} on {args.detector}/{args.system} (K={K}): "
          f"mean safe_fraction={mean_frac:.3f}  |  majority-vulnerable {n_maj_vuln}/{n_done} "
          f"= {(n_maj_vuln/n_done if n_done else 0):.1%}")
    print(f"[recovery] per-slug CSV → {out_path}")
    print(f"[recovery] reasoning sidecar → {side_path}")
    print("[recovery] safe_fraction = P(safe) estimate per attack. For D0 this is "
          "attack robustness; for D1 vs D0 (same slug/framing) it is the defense effect.")


if __name__ == "__main__":
    main()
