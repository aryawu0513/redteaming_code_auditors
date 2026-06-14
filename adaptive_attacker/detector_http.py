"""
detector_http.py — HTTP client for a running detector_server.py.

Same interface as OpenVulDetector / VulnLLMRDetector so refine_loop.py can use
a server-resident detector instead of loading the model in-process. This avoids
double-loading the OpenVul model on a second GPU when the detector is already
served on port 8008.

Methods:
    detect(record) -> {"verdict", "reasoning", "votes", "all_outputs"}
    detect_batch(records) -> list of the above dicts, in order
"""
from __future__ import annotations

import os

import requests


class HttpDetectorClient:
    def __init__(self, base_url: str, timeout: float | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout if timeout is not None else float(
            os.environ.get("DETECTOR_HTTP_TIMEOUT", "7200")
        )

        try:
            r = requests.get(f"{self.base_url}/health", timeout=10)
            r.raise_for_status()
            info = r.json()
            print(f"[detector_http] connected: {info} (timeout={self.timeout}s)", flush=True)
        except Exception as e:
            raise RuntimeError(
                f"detector server health check failed at {self.base_url}: {e}"
            ) from e

        # Probe for /detect_batch once at startup so we know whether to send
        # batches or fall back to looped /detect.
        try:
            schema = requests.get(f"{self.base_url}/openapi.json", timeout=5).json()
            self._has_batch = "/detect_batch" in schema.get("paths", {})
        except Exception:
            self._has_batch = False
        print(f"[detector_http] /detect_batch available: {self._has_batch}", flush=True)

    @staticmethod
    def _body(record: dict) -> dict:
        return {
            "code": record.get("code", ""),
            "context": record.get("context", ""),
            "target_function": record["target_function"],
            "function_name": record["function_name"],
            "file_name": record.get("file_name", "solution.c"),
        }

    @staticmethod
    def _normalize(data: dict) -> dict:
        reasoning = data.get("reasoning", "")
        return {
            "verdict": data["verdict"],
            "reasoning": reasoning,
            "votes": data.get("votes", {}),
            "all_outputs": [reasoning],
        }

    def detect(self, record: dict, mode: str = "npd") -> dict:
        # `mode` is ignored — the server picks its own prompt mode at startup.
        r = requests.post(
            f"{self.base_url}/detect", json=self._body(record), timeout=self.timeout
        )
        r.raise_for_status()
        return self._normalize(r.json())

    def detect_batch(self, records: list[dict], mode: str = "npd") -> list[dict]:
        if not records:
            return []
        if not self._has_batch:
            return [self.detect(rec) for rec in records]

        body = {"records": [self._body(r) for r in records]}
        r = requests.post(
            f"{self.base_url}/detect_batch", json=body, timeout=self.timeout
        )
        if r.status_code == 404:
            # Server changed under us — disable and fall back for the rest of the run.
            self._has_batch = False
            return [self.detect(rec) for rec in records]
        r.raise_for_status()
        results = r.json()["results"]
        return [self._normalize(x) for x in results]
