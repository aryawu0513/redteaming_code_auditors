"""
detector_server.py — Thin FastAPI wrapper around OpenVulDetector / VulnLLMRDetector.

Loads one detector model in-process and exposes POST /detect so the mini-swe-agent
can invoke detection via the shell instead of importing Python.

Usage:
    python attacker/adaptive/detector_server.py --detector openvul  --port 8008
    python attacker/adaptive/detector_server.py --detector vulnllmr --port 8008

POST /detect
    body: full OpenVul-format record dict
          (required keys: code, context, target_function, function_name, file_name)
    returns: {"verdict": "safe"|"vulnerable", "reasoning": str, "votes": {...}}
"""
import argparse
import sys
import threading
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))


app = FastAPI()
DETECTOR = None
DEFENSE_NAME = None  # normalized defense the server bakes in ("D0" = none)
_DETECT_LOCK = threading.Lock()


@app.get("/health")
def health() -> dict:
    return {"ok": True, "detector": type(DETECTOR).__name__ if DETECTOR else None,
            "defense": DEFENSE_NAME}


@app.post("/detect")
async def detect(request: Request) -> dict:
    if DETECTOR is None:
        raise HTTPException(status_code=500, detail="detector not loaded")
    record = await request.json()
    try:
        with _DETECT_LOCK:
            result = DETECTOR.detect(record)
    except Exception as exc:
        print(f"[server] detect() raised: {exc}", flush=True)
        return {"verdict": "error", "reasoning": f"scan error: {exc}", "votes": {}}
    return {"verdict": result["verdict"], "reasoning": result["reasoning"],
            "votes": result.get("votes", {})}


@app.post("/detect_batch")
async def detect_batch(request: Request) -> dict:
    if DETECTOR is None:
        raise HTTPException(status_code=500, detail="detector not loaded")
    body = await request.json()
    records = body.get("records", [])
    if not records:
        return {"results": []}
    try:
        with _DETECT_LOCK:
            results = DETECTOR.detect_batch(records)
    except Exception as exc:
        print(f"[server] detect_batch() raised: {exc}", flush=True)
        results = [{"verdict": "error", "reasoning": f"scan error: {exc}", "votes": {}}
                   for _ in records]
    return {"results": [{"verdict": r["verdict"], "reasoning": r["reasoning"],
                         "votes": r.get("votes", {})} for r in results]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", choices=["openvul", "vulnllmr", "repoaudit", "vultrial", "vulrag"], required=True)
    parser.add_argument("--port", type=int, default=8008)
    parser.add_argument("--tp", type=int, default=1,
                        help="vLLM tensor parallel size")
    parser.add_argument("--model", default=None,
                        help="Override detector model id")
    parser.add_argument("--vulnllmr-mode", choices=["agentic", "funclevel"],
                        default="funclevel",
                        help="VulnLLM-R only: 'funclevel' (published snippet classifier, "
                             "matches the attack + recovery defaults) or 'agentic' (scaffold).")
    parser.add_argument("--cwe", type=int, default=476,
                        help="Which CWE to hunt for (476=NPD, 416=UAF). "
                             "Used by vulnllmr and openvul.")
    parser.add_argument("--defense", default="D0",
                        help="Defense baked into the served model's prompt: "
                             "D0 (none) or a registry key (D1, D3, D4). Applied to "
                             "every /detect call for the life of the server. D3/D4 "
                             "additionally prescreen target_function live via the "
                             "screening agent (see defenses/screening_cache.py).")
    parser.add_argument("--baseline-source-system", default=None,
                        help="D5 only: system dir under adaptive_attacker/results/ "
                             "whose baseline_gate_{tag}.json to reuse as the D5 Prior "
                             "Analysis anchor, instead of paying for a fresh undefended "
                             "call per unique clean function. Defaults to the standard "
                             "D0 collection dir for --detector (openvul_full / "
                             "vulnllmr_funclevel_full) — only pass this to override, "
                             "e.g. for a non-standard dataset. Harmless (unused) for any "
                             "defense other than D5 — no downside to leaving it defaulted.")
    parser.add_argument("--baseline-source-tag", default="fromscratch_v1",
                        help="Run-tag suffix of --baseline-source-system's gate files.")
    args = parser.parse_args()

    # Auto-derive the D0 source rather than requiring it be passed every time —
    # it's a no-op for every defense except D5, so there's no cost to always
    # having a correct default.
    _DEFAULT_BASELINE_SOURCE_SYSTEM = {
        "openvul": "openvul_full",
        "vulnllmr": "vulnllmr_funclevel_full" if args.vulnllmr_mode == "funclevel" else None,
        "vulrag": "vulrag_full",
        "vultrial": "vultrial_full",
    }
    baseline_source_system = (args.baseline_source_system
                               or _DEFAULT_BASELINE_SOURCE_SYSTEM.get(args.detector))
    baseline_source = (baseline_source_system, args.baseline_source_tag) if baseline_source_system else None

    # Resolve defense text from the registry once, at load time.
    defense_text = None
    screening_variant = None
    steering = None
    if args.defense and args.defense.upper() not in ("D0", "NONE"):
        sys.path.insert(0, str(HERE.parent))
        from defenses.registry import DEFENSES
        if args.defense not in DEFENSES:
            parser.error(f"unknown defense {args.defense!r}; known: D0, {list(DEFENSES)}")
        defense_text = DEFENSES[args.defense]["task_addition"]
        screening_variant = DEFENSES[args.defense].get("screening_variant")
        steering = DEFENSES[args.defense].get("steering")
    print(f"[server] defense={args.defense} ({'ON' if defense_text else 'OFF'}) "
          f"screening={screening_variant or 'OFF'} steering={steering or 'OFF'}", flush=True)

    global DETECTOR, DEFENSE_NAME
    DEFENSE_NAME = "D0" if defense_text is None else args.defense
    if args.detector == "openvul":
        from detector_openvul import OpenVulDetector
        cwe_to_mode = {476: "npd", 416: "uaf"}
        kwargs = {"tp": args.tp, "mode": cwe_to_mode.get(args.cwe, "generic"),
                  "defense_text": defense_text, "screening_variant": screening_variant,
                  "steering": steering, "baseline_source": baseline_source}
        if args.model:
            kwargs["model_id"] = args.model
        DETECTOR = OpenVulDetector(**kwargs)
    elif args.detector == "vulnllmr":
        from detector_vulnllmr import VulnLLMRDetector
        kwargs = {"tp": args.tp, "mode": args.vulnllmr_mode, "cwe": args.cwe,
                  "defense_text": defense_text, "screening_variant": screening_variant,
                  "steering": steering, "baseline_source": baseline_source}
        if args.model:
            kwargs["model_id"] = args.model
        DETECTOR = VulnLLMRDetector(**kwargs)
    elif args.detector == "repoaudit":
        from detector_repoaudit import RepoAuditDetector
        kwargs = {}
        if args.model:
            kwargs["model_name"] = args.model
        DETECTOR = RepoAuditDetector(**kwargs)
    elif args.detector == "vulrag":
        from detector_vulrag import VulRAGDetector
        kwargs = {"defense_text": defense_text, "screening_variant": screening_variant,
                  "steering": steering, "baseline_source": baseline_source}
        if args.model:
            kwargs["model"] = args.model
        DETECTOR = VulRAGDetector(**kwargs)
    else:
        from detector_vultrial import VulTrialDetector
        kwargs = {"defense_text": defense_text, "screening_variant": screening_variant,
                  "steering": steering, "baseline_source": baseline_source}
        if args.model:
            kwargs["model"] = args.model
        DETECTOR = VulTrialDetector(**kwargs)

    print(f"[server] {args.detector} loaded; serving on 0.0.0.0:{args.port}", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning",
                timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()
