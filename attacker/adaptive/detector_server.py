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
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))


class DetectRequest(BaseModel):
    code: str
    context: str = ""
    target_function: str
    function_name: str
    file_name: str = "solution.c"


app = FastAPI()
DETECTOR = None
_DETECT_LOCK = threading.Lock()


@app.get("/health")
def health() -> dict:
    return {"ok": True, "detector": type(DETECTOR).__name__ if DETECTOR else None}


@app.post("/detect")
def detect(req: DetectRequest) -> dict:
    if DETECTOR is None:
        raise HTTPException(status_code=500, detail="detector not loaded")
    record = req.model_dump()
    try:
        with _DETECT_LOCK:
            result = DETECTOR.detect(record)
    except Exception as exc:
        # Return error verdict rather than crashing the server on bad inputs
        # (e.g. C++ header-only files that tree-sitter can't parse as C)
        print(f"[server] detect() raised: {exc}", flush=True)
        return {
            "verdict": "error",
            "reasoning": f"scan error: {exc}",
            "votes": {},
        }
    return {
        "verdict": result["verdict"],
        "reasoning": result["reasoning"],
        "votes": result.get("votes", {}),
    }


class DetectBatchRequest(BaseModel):
    records: list[DetectRequest]


@app.post("/detect_batch")
def detect_batch(req: DetectBatchRequest) -> dict:
    """
    Batched detect — one server call covers N records. For OpenVul this maps to
    a single LLM.generate(prompts) and benefits from vLLM continuous batching;
    for VulnLLM-R it loops internally (the agent scaffold doesn't batch across
    records).
    """
    if DETECTOR is None:
        raise HTTPException(status_code=500, detail="detector not loaded")
    records = [r.model_dump() for r in req.records]
    try:
        with _DETECT_LOCK:
            results = DETECTOR.detect_batch(records)
    except Exception as exc:
        print(f"[server] detect_batch() raised: {exc}", flush=True)
        results = [{"verdict": "error", "reasoning": f"scan error: {exc}",
                    "votes": {}}
                   for _ in records]
    return {
        "results": [
            {
                "verdict": r["verdict"],
                "reasoning": r["reasoning"],
                "votes": r.get("votes", {}),
            }
            for r in results
        ]
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", choices=["openvul", "vulnllmr", "repoaudit", "vultrial"], required=True)
    parser.add_argument("--port", type=int, default=8008)
    parser.add_argument("--tp", type=int, default=1,
                        help="vLLM tensor parallel size")
    parser.add_argument("--model", default=None,
                        help="Override detector model id")
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
        kwargs = {"tp": args.tp}
        if args.model:
            kwargs["model_id"] = args.model
        DETECTOR = VulnLLMRDetector(**kwargs)
    elif args.detector == "repoaudit":
        from detector_repoaudit import RepoAuditDetector
        kwargs = {}
        if args.model:
            kwargs["model_name"] = args.model
        DETECTOR = RepoAuditDetector(**kwargs)
    else:
        from detector_vultrial import VulTrialDetector
        kwargs = {}
        if args.model:
            kwargs["model"] = args.model
        DETECTOR = VulTrialDetector(**kwargs)

    print(f"[server] {args.detector} loaded; serving on 0.0.0.0:{args.port}", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
