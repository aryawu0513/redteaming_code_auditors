"""
detector_vultrial.py — VulTrial wrapper with OpenVulDetector-like interface.
"""
from __future__ import annotations

import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from VulTrial.run import run_evaluation


class _Args:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class VulTrialDetector:
    """
    Runs VulTrial on a one-record dataset dir.
    Verdict: vulnerable if predicted_is_vulnerable == "yes".
    Reasoning: raw output text from VulTrial.
    """

    def __init__(self, model: str = "gpt-4o", mode: str = "npd") -> None:
        self.model = model
        self.mode = mode
        self.thread_safe = True  # OpenAI API calls; no shared engine state

    def detect(self, record: dict) -> dict:
        with tempfile.TemporaryDirectory(prefix="vultrial_det_") as tmp:
            ds_dir = Path(tmp) / "dataset"
            ds_dir.mkdir(parents=True, exist_ok=True)
            # Name file so VulTrial parses attack type cleanly.
            slug = record.get("slug") or "record"
            attack = record.get("variant") or "CLEAN"
            # VulTrial reads `code`, `target`, `idx` from the record JSON.
            # Send only the target_function — VulTrial is designed for focused snippets.
            tf = record.get("target_function", "")
            vultrial_record = {
                **record,
                "code":   tf,
                "target": record.get("target", 1),
                "idx":    record.get("idx", 0),
            }
            ds_path = ds_dir / f"{slug}_{attack}.json"
            ds_path.write_text(json.dumps([vultrial_record], indent=2))

            args = _Args(
                dataset_path=str(ds_dir),
                output_dir=str(Path(tmp) / "out"),
                variant=slug,
                mode=self.mode,
                model=self.model,
                category="context_aware",
                language="c",
                save=True,
            )
            results = run_evaluation(args)
            if not results:
                return {"verdict": "safe", "reasoning": "VulTrial produced no results.", "votes": {}}
            r = results[0]
            predicted = r.get("predicted_is_vulnerable", "")
            if predicted == "yes":
                verdict = "vulnerable"
            elif predicted in ("no",):
                verdict = "safe"
            else:
                verdict = "error"  # unknown = subprocess/parse failure, not a clean safe
            reasoning = r.get("output", "")
            return {"verdict": verdict, "reasoning": reasoning, "votes": {}}

    def detect_batch(self, records: list[dict]) -> list[dict]:
        with ThreadPoolExecutor(max_workers=len(records)) as ex:
            return list(ex.map(self.detect, records))
