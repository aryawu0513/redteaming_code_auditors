"""
detector_vultrial.py — VulTrial wrapper with OpenVulDetector-like interface.
"""
from __future__ import annotations

import json
import tempfile
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

    def detect(self, record: dict) -> dict:
        with tempfile.TemporaryDirectory(prefix="vultrial_det_") as tmp:
            ds_dir = Path(tmp) / "dataset"
            ds_dir.mkdir(parents=True, exist_ok=True)
            # Name file so VulTrial parses attack type cleanly.
            slug = record.get("slug") or "record"
            attack = record.get("variant") or "CLEAN"
            # VulTrial reads `code`, `target`, `idx` from the record JSON.
            # Construct code from separate fields; inject defaults for the rest.
            before = record.get("context_before", record.get("context", ""))
            after  = record.get("context_after", "")
            tf     = record.get("target_function", "")
            parts  = [p for p in [before, tf, after] if p]
            vultrial_record = {
                **record,
                "code":   "\n\n".join(parts),
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
            verdict = "vulnerable" if predicted == "yes" else "safe"
            reasoning = r.get("output", "")
            return {"verdict": verdict, "reasoning": reasoning, "votes": {}}

    def detect_batch(self, records: list[dict]) -> list[dict]:
        return [self.detect(r) for r in records]
