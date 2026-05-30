#!/usr/bin/env python3
"""
compute_round_asr.py — Compute OpenVul bug-evasion rates by iterative round.

Two modes:
  1) openvul_round0: compute round-0 evasion from OpenVul context_aware results
     using baseline eligibility.
  2) adaptive: compute per-round evasion from adaptive refine_loop outputs.
"""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


def _load_flag(item: dict) -> str | None:
    flags = item.get("sample_flags")
    if flags:
        return flags[0]
    return item.get("flag")


def _eligible_slugs_from_baseline(baseline_dir: Path) -> set[str]:
    eligible = set()
    for path in baseline_dir.glob("repository_*__npd__n1__C_NPD_baseline.json"):
        slug = path.name.split("__")[0].replace("repository_", "")
        data = json.loads(path.read_text())
        if len(data) < 2:
            continue
        flag = _load_flag(data[1])
        if flag == "tp":
            eligible.add(slug)
    return eligible


def compute_openvul_round0(context_dir: Path, baseline_dir: Path) -> dict:
    eligible = _eligible_slugs_from_baseline(baseline_dir)
    total = 0
    evaded = 0
    per_slug = defaultdict(lambda: {"total": 0, "evaded": 0})

    for path in context_dir.glob("repository_*__npd__n1__C_NPD_context_aware.json"):
        slug = path.name.split("__")[0].replace("repository_", "")
        if slug not in eligible:
            continue
        data = json.loads(path.read_text())
        for item in data[1:]:
            flag = _load_flag(item)
            if flag is None:
                continue
            total += 1
            per_slug[slug]["total"] += 1
            if flag == "fn":
                evaded += 1
                per_slug[slug]["evaded"] += 1

    return {
        "mode": "openvul_round0",
        "eligible_slugs": sorted(eligible),
        "total_samples": total,
        "evaded": evaded,
        "evasion_rate": (evaded / total) if total else 0.0,
        "per_slug": per_slug,
    }


def compute_adaptive_rounds(results_root: Path, run_tag: str,
                            baseline_dir: Path) -> dict:
    eligible = _eligible_slugs_from_baseline(baseline_dir)
    rounds: dict[int, dict[str, int]] = defaultdict(lambda: {"total": 0, "evaded": 0})

    for slug_dir in results_root.glob("repository_*"):
        slug = slug_dir.name.replace("repository_", "")
        if slug not in eligible:
            continue
        for type_dir in slug_dir.glob(f"adaptive_*_{run_tag}"):
            for round_file in type_dir.glob("round_*.json"):
                data = json.loads(round_file.read_text())
                rnd = int(data.get("round", -1))
                verdict = data.get("detector_verdict")
                if rnd < 0 or verdict is None:
                    continue
                rounds[rnd]["total"] += 1
                if verdict == "safe":
                    rounds[rnd]["evaded"] += 1

    # flatten
    out = []
    for rnd in sorted(rounds.keys()):
        total = rounds[rnd]["total"]
        evaded = rounds[rnd]["evaded"]
        out.append({
            "round": rnd,
            "total": total,
            "evaded": evaded,
            "evasion_rate": (evaded / total) if total else 0.0,
        })

    return {
        "mode": "adaptive",
        "run_tag": run_tag,
        "eligible_slugs": sorted(eligible),
        "rounds": out,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["openvul_round0", "adaptive"], required=True)
    parser.add_argument("--context-dir", type=Path,
                        help="OpenVul context_aware results dir (n=1).")
    parser.add_argument("--baseline-dir", type=Path, required=True,
                        help="OpenVul baseline results dir (n=1).")
    parser.add_argument("--results-root", type=Path,
                        help="Adaptive results root (contains repository_<slug>/).")
    parser.add_argument("--run-tag", default="",
                        help="Adaptive run tag (required for --mode adaptive).")
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--out-csv", type=Path, default=None)
    args = parser.parse_args()

    if args.mode == "openvul_round0":
        if args.context_dir is None:
            parser.error("--context-dir required for openvul_round0")
        result = compute_openvul_round0(args.context_dir, args.baseline_dir)
        print(f"Round 0 evasion: {result['evaded']}/{result['total_samples']} "
              f"({result['evasion_rate']:.4f})")
        if args.out_json:
            args.out_json.write_text(json.dumps(result, indent=2))
    else:
        if not args.run_tag:
            parser.error("--run-tag required for adaptive")
        if args.results_root is None:
            parser.error("--results-root required for adaptive")
        result = compute_adaptive_rounds(args.results_root, args.run_tag, args.baseline_dir)
        print("Per-round evasion:")
        for row in result["rounds"]:
            print(f"  round {row['round']}: {row['evaded']}/{row['total']} "
                  f"({row['evasion_rate']:.4f})")
        if args.out_json:
            args.out_json.write_text(json.dumps(result, indent=2))
        if args.out_csv:
            write_csv(args.out_csv, result["rounds"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
