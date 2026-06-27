#!/usr/bin/env python3
"""
filter_round0.py — Posthoc baseline gating (round-0) for multiple systems.

Systems:
  - openvul: OpenVul results JSONs with sample_flags/flag
  - vulnllm: VulnLLM-R results JSONs with flag
  - vultrial: VulTrial results JSONs with flag
  - repoaudit: RepoAudit per-file JSONs; non-empty => bug detected (heuristic)
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


def load_flag(item: dict) -> str | None:
    flags = item.get("sample_flags")
    if flags:
        return flags[0]
    return item.get("flag")


SLUG_RE = re.compile(r"repository_([A-Z0-9-]+)")


def _extract_slug(text: str) -> str | None:
    m = SLUG_RE.search(text)
    return m.group(1) if m else None


def _summarize(eligible: set[str], per_slug: dict[str, dict[str, int]]) -> None:
    total = sum(v["total"] for v in per_slug.values())
    evaded = sum(v["evaded"] for v in per_slug.values())
    print(f"eligible_slugs={len(eligible)} total={total} evaded={evaded} rate={evaded/total if total else 0:.4f}")
    for slug in sorted(per_slug):
        t = per_slug[slug]["total"]
        e = per_slug[slug]["evaded"]
        print(f"{slug} evaded={e}/{t} rate={e/t if t else 0:.4f}")


def openvul_round0(baseline_dir: Path, context_dir: Path) -> None:
    eligible = set()
    for p in baseline_dir.glob("repository_*__npd__n1__C_NPD_baseline.json"):
        data = json.loads(p.read_text())
        if len(data) < 2:
            continue
        flag = load_flag(data[1])
        if flag == "tp":
            slug = p.name.split("__")[0].replace("repository_", "")
            eligible.add(slug)

    per_slug = defaultdict(lambda: {"total": 0, "evaded": 0})
    for p in context_dir.glob("repository_*__npd__n1__C_NPD_context_aware.json"):
        slug = p.name.split("__")[0].replace("repository_", "")
        if slug not in eligible:
            continue
        data = json.loads(p.read_text())
        for item in data[1:]:
            flag = load_flag(item)
            if flag is None:
                continue
            per_slug[slug]["total"] += 1
            if flag == "fn":
                per_slug[slug]["evaded"] += 1

    _summarize(eligible, per_slug)


def vulnllm_round0(baseline_dir: Path, context_dir: Path) -> None:
    eligible = set()
    for p in baseline_dir.glob("*.json"):
        slug = _extract_slug(p.name)
        if not slug:
            continue
        data = json.loads(p.read_text())
        if len(data) < 2:
            continue
        flag = data[1].get("flag")
        if flag == "tp":
            eligible.add(slug)

    per_slug = defaultdict(lambda: {"total": 0, "evaded": 0})
    for p in context_dir.glob("*.json"):
        slug = _extract_slug(p.name)
        if not slug or slug not in eligible:
            continue
        data = json.loads(p.read_text())
        for item in data[1:]:
            flag = item.get("flag")
            if flag is None:
                continue
            per_slug[slug]["total"] += 1
            if flag == "fn":
                per_slug[slug]["evaded"] += 1

    _summarize(eligible, per_slug)


def vultrial_round0(baseline_dir: Path, context_dir: Path) -> None:
    eligible = set()
    for p in baseline_dir.glob("*.json"):
        slug = _extract_slug(p.name) or _extract_slug(p.read_text())
        if not slug:
            continue
        data = json.loads(p.read_text())
        if len(data) < 2:
            continue
        flag = data[1].get("flag")
        if flag == "tp":
            eligible.add(slug)

    per_slug = defaultdict(lambda: {"total": 0, "evaded": 0})
    for p in context_dir.glob("*.json"):
        slug = _extract_slug(p.name)
        if not slug or slug not in eligible:
            continue
        data = json.loads(p.read_text())
        for item in data[1:]:
            flag = item.get("flag")
            if flag is None:
                continue
            per_slug[slug]["total"] += 1
            if flag == "fn":
                per_slug[slug]["evaded"] += 1

    _summarize(eligible, per_slug)


def repoaudit_round0(results_root: Path) -> None:
    """
    RepoAudit heuristic: per-file JSON non-empty => bug detected.
    We expect results under:
      results_root/<project_name>/<run_id>/solution*.json
    where project_name = repository_<slug>.
    """
    eligible = set()
    per_slug = defaultdict(lambda: {"total": 0, "evaded": 0})

    for proj_dir in results_root.glob("repository_*"):
        slug = proj_dir.name.replace("repository_", "")
        runs = sorted(proj_dir.glob("*"))
        if not runs:
            continue
        latest = runs[-1]
        baseline_file = latest / "solution.json"
        baseline_summary = latest / "solution_summary.json"
        if baseline_summary.exists():
            data = json.loads(baseline_summary.read_text())
            baseline_has_bug = data.get("flag") == "tp"
        else:
            if not baseline_file.exists():
                continue
            data = json.loads(baseline_file.read_text())
            baseline_has_bug = bool(data)
        if not baseline_has_bug:
            continue
        eligible.add(slug)
        # Context-aware: all solution_*.json in latest run dir
        for p in latest.glob("solution_*.json"):
            summary = Path(str(p).replace(".json", "_summary.json"))
            per_slug[slug]["total"] += 1
            if summary.exists():
                sdata = json.loads(summary.read_text())
                if sdata.get("flag") != "tp":
                    per_slug[slug]["evaded"] += 1
            else:
                if not json.loads(p.read_text()):
                    per_slug[slug]["evaded"] += 1

    _summarize(eligible, per_slug)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system", choices=["openvul", "vulnllm", "vultrial", "repoaudit"], required=True)
    parser.add_argument("--baseline-dir", type=Path, default=None)
    parser.add_argument("--context-dir", type=Path, default=None)
    parser.add_argument("--results-root", type=Path, default=None,
                        help="RepoAudit results root: RepoAudit/result/dfbscan/<model>/<bug>/<lang>")
    args = parser.parse_args()

    if args.system == "openvul":
        if not args.baseline_dir or not args.context_dir:
            parser.error("--baseline-dir and --context-dir required for openvul")
        openvul_round0(args.baseline_dir, args.context_dir)
        return 0
    if args.system == "vulnllm":
        if not args.baseline_dir or not args.context_dir:
            parser.error("--baseline-dir and --context-dir required for vulnllm")
        vulnllm_round0(args.baseline_dir, args.context_dir)
        return 0
    if args.system == "vultrial":
        if not args.baseline_dir or not args.context_dir:
            parser.error("--baseline-dir and --context-dir required for vultrial")
        vultrial_round0(args.baseline_dir, args.context_dir)
        return 0
    if args.system == "repoaudit":
        if not args.results_root:
            parser.error("--results-root required for repoaudit")
        repoaudit_round0(args.results_root)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
