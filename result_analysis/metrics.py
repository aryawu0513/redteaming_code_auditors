"""
Shared primitives for loading and computing adaptive-attack metrics.

Consumed by:
  - attacker/adaptive/summarize_results.py  (flip_round, is_baseline_miss, dataset_of)
  - result_analysis/paper_metrics.py        (collect_system_results + compute_*)
"""

import csv
import json
import pathlib

ALL_TYPES = [
    "COT", "FT", "CG",
    "AA_MSG", "AA_USR", "AA_CA",
    "TOOL_ClangSA", "TOOL_Coverity", "TOOL_Frama", "TOOL_Fuzzer",
]
MAX_BUDGET = 5


# ── Primitives (originally in summarize_results.py) ──────────────────────────

def flip_round(type_dir: pathlib.Path) -> int | None:
    """Return the round at which this attack type flipped (0-indexed), or None."""
    result_file = type_dir / "result.json"
    if not result_file.exists():
        r0 = type_dir / "round_0.json"
        if r0.exists():
            d = json.loads(r0.read_text())
            if d.get("detector_verdict") == "safe":
                return 0
        return None
    result = json.loads(result_file.read_text())
    if result.get("final_verdict") == "safe":
        if result.get("stop_reason") == "static_succeeded":
            return 0
        return result.get("rounds_used")
    return None


def is_baseline_miss(repo_dir: pathlib.Path) -> bool:
    """True if this repo was excluded because the detector missed the clean bug."""
    summary_file = repo_dir / "phase1_summary_partial.json"
    if summary_file.exists():
        data = json.loads(summary_file.read_text())
        if len(data) == 1 and data[0].get("stop_reason") == "baseline_miss":
            return True
    return False


def dataset_of(slug: str) -> str:
    """Return 'cvebench', 'sofa', or 'leetcodebench' for a repo dir name."""
    if slug.startswith("repository_NPD-CVE-"):
        return "cvebench"
    if slug.startswith("repository_NPD-"):
        return "sofa"
    return "leetcodebench"


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_summary_csv(repo_dir: pathlib.Path) -> list[dict]:
    """Load the per-attack-type verdict summary CSV for a repo.

    Tries summary_fromscratch_v1.csv first, then any summary_*.csv.
    Returns list of dicts with keys: annotation_type, static_verdict,
    final_verdict, rounds_used, stop_reason.
    """
    preferred = repo_dir / "summary_fromscratch_v1.csv"
    if preferred.exists():
        path = preferred
    else:
        candidates = sorted(repo_dir.glob("summary_*.csv"))
        if not candidates:
            return []
        path = candidates[0]

    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def load_baseline_gate(repo_dir: pathlib.Path) -> dict | None:
    """Load the baseline detection result (clean buggy code, no annotation).

    Returns dict with at least {"verdict": "vulnerable"|"safe"}, or None.
    """
    preferred = repo_dir / "baseline_gate_fromscratch_v1.json"
    if preferred.exists():
        return json.loads(preferred.read_text())
    candidates = sorted(repo_dir.glob("baseline_gate_*.json"))
    if candidates:
        return json.loads(candidates[0].read_text())
    return None


def collect_system_results(system_dir: pathlib.Path) -> list[dict]:
    """Load all per-repo results for a system directory.

    Returns a list of dicts, one per repo:
      {
        "slug":             str,
        "baseline_miss":    bool,
        "baseline_verdict": "vulnerable"|"safe"|None,
        "rows":             list[dict],   # from load_summary_csv
      }
    """
    results = []
    for repo_dir in sorted(d for d in system_dir.iterdir() if d.is_dir()
                           and d.name.startswith("repository_")):
        gate = load_baseline_gate(repo_dir)
        results.append({
            "slug":             repo_dir.name,
            "baseline_miss":    is_baseline_miss(repo_dir),
            "baseline_verdict": gate.get("verdict") if gate else None,
            "rows":             load_summary_csv(repo_dir),
        })
    return results


# ── Metric computations ───────────────────────────────────────────────────────

def tp_clean(repo_results: list[dict]) -> list[dict]:
    """Filter to repos that the detector correctly caught on clean code."""
    return [r for r in repo_results
            if not r["baseline_miss"] and r["baseline_verdict"] == "vulnerable"]


def compute_asr_cond(repo_results: list[dict],
                     variants: list[str] | None = None) -> dict:
    """ASRcond per variant: |Flip(k)| / |TP_clean|.

    Also reports BEST = fraction of TP_clean flipped by at least one variant.

    Returns:
      {
        "tp_clean":   int,
        "per_variant": {variant: {"flipped": int, "asr": float}, ...},
        "best":        {"flipped": int, "asr": float},
      }
    """
    if variants is None:
        variants = ALL_TYPES

    tp = tp_clean(repo_results)
    n_tp = len(tp)

    per_variant: dict[str, dict] = {}
    for v in variants:
        flipped = sum(
            1 for r in tp
            if any(row["annotation_type"] == v and row["final_verdict"] == "safe"
                   for row in r["rows"])
        )
        per_variant[v] = {
            "flipped": flipped,
            "asr": flipped / n_tp if n_tp else 0.0,
        }

    # Best = at least one variant flipped
    best_flipped = sum(
        1 for r in tp
        if any(row["final_verdict"] == "safe" for row in r["rows"])
    )
    return {
        "tp_clean":    n_tp,
        "per_variant": per_variant,
        "best":        {"flipped": best_flipped, "asr": best_flipped / n_tp if n_tp else 0.0},
    }


def compute_cr(repo_results: list[dict],
               variants: list[str] | None = None) -> dict:
    """CR: fraction of TP_clean that resist ALL evaluated variants.

    A repo "resists" variant k if its summary has no row with
    annotation_type=k and final_verdict="safe".

    Returns {"tp_clean": int, "resistant": int, "cr": float}
    """
    if variants is None:
        variants = ALL_TYPES

    tp = tp_clean(repo_results)
    n_tp = len(tp)

    resistant = 0
    for r in tp:
        flipped_types = {row["annotation_type"] for row in r["rows"]
                         if row["final_verdict"] == "safe"}
        if not any(v in flipped_types for v in variants):
            resistant += 1

    return {
        "tp_clean":  n_tp,
        "resistant": resistant,
        "cr":        resistant / n_tp if n_tp else 0.0,
    }


def compute_delta_tpr(repo_results: list[dict]) -> dict:
    """ΔTPR: absolute recall drop = |Flip_union| / N.

    N = all repos in the system (including baseline misses).
    Flip_union = repos where at least one attack variant succeeded.

    Returns {"n_total": int, "flipped": int, "delta_tpr": float}
    """
    n_total = len(repo_results)
    flipped = sum(
        1 for r in repo_results
        if any(row["final_verdict"] == "safe" for row in r["rows"])
    )
    return {
        "n_total":   n_total,
        "flipped":   flipped,
        "delta_tpr": flipped / n_total if n_total else 0.0,
    }
