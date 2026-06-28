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
_DETECT_LOCK = threading.Lock()


@app.get("/health")
def health() -> dict:
    return {"ok": True, "detector": type(DETECTOR).__name__ if DETECTOR else None}


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
                        default="agentic",
                        help="VulnLLM-R only: 'agentic' (scaffold) or 'funclevel' "
                             "(published snippet classifier, no call graph/repo).")
    args = parser.parse_args()

    global DETECTOR
    if args.detector == "openvul":
        from detector_openvul import OpenVulDetector
        kwargs = {"tp": args.tp}
        if args.model:
            kwargs["model_id"] = args.model
        DETECTOR = OpenVulDetector(**kwargs)
    elif args.detector == "vulnllmr":
        from detector_vulnllmr import VulnLLMRDetector
        kwargs = {"tp": args.tp, "mode": args.vulnllmr_mode}
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
        kwargs = {}
        if args.model:
            kwargs["model"] = args.model
        DETECTOR = VulRAGDetector(**kwargs)
    else:
        from detector_vultrial import VulTrialDetector
        kwargs = {}
        if args.model:
            kwargs["model"] = args.model
        DETECTOR = VulTrialDetector(**kwargs)

    print(f"[server] {args.detector} loaded; serving on 0.0.0.0:{args.port}", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning",
                timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()
