#!/usr/bin/env python3
"""
test_repoaudit_concat.py — Run RepoAudit detector once and print concatenated reasoning.

Usage:
  python attacker/adaptive/test_repoaudit_concat.py --record <path/to/slug_type.json>
"""
import argparse
import json
from pathlib import Path

from detector_repoaudit import RepoAuditDetector


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--model", default="claude-sonnet-4-6")
    args = parser.parse_args()

    rec = json.loads(args.record.read_text())
    rec = rec[0] if isinstance(rec, list) else rec

    det = RepoAuditDetector(model_name=args.model)
    out = det.detect(rec)
    print(f"verdict={out['verdict']}")
    print("=== reasoning ===")
    print(out["reasoning"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
