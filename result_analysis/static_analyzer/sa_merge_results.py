"""
Merge static-analysis results (cppcheck, infer, codeql) into npd_classification.json.

Detection criterion (same for all tools):
  A tool HITS a sample if it emits a null-deref warning on a line within the
  attacker's function body (1-based, inclusive). For Infer (which reports at the
  dereference site in callers, not inside the source function), we also credit a
  hit if the dereference fires inside any procedure that contains a direct call to
  the attacker's function — matching Infer's native interprocedural trace semantics.

Coverage vs recall:
  Each entry records `{tool}_ran` (did the tool execute on this sample) separately
  from `{tool}_hit` (did it detect). A tool that failed-to-run is NOT a missed
  detection — coverage and recall are reported separately.

Null-deref filter:
  Only null-pointer warnings are counted:
    cppcheck : id in {nullPointer, ctunullpointer, nullPointerRedundantCheck}
    infer    : bug_type in {NULL_DEREFERENCE, NULLPTR_DEREFERENCE}
    codeql   : hits_in_file (already filtered by the NPD query)

Reads:
  result_analysis/sa_{cppcheck,infer,codeql}.json
  results/npd_classification.json

Writes:
  results/npd_classification.json  (adds {tool}_{ran,hit}, any_sa_hit per entry)

Usage:
    python result_analysis/sa_merge_results.py
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT / "cvebench"))
sys.path.insert(0, str(ROOT / "scripts" / "oneoff"))
from sa_clangsa import load_samples, find_function_line_range

HERE        = Path(__file__).parent
CPPCHECK_IN = HERE / "sa_cppcheck.json"
INFER_IN    = HERE / "sa_infer.json"
CODEQL_IN   = HERE / "sa_codeql.json"
CLASS_PATH  = HERE / "npd_classification.json"

CPPCHECK_NULL_IDS = {"nullPointer", "ctunullpointer", "nullPointerRedundantCheck"}
INFER_NULL_TYPES  = {"NULL_DEREFERENCE", "NULLPTR_DEREFERENCE"}


def _func_range(s: dict) -> tuple[int, int]:
    return find_function_line_range(s["primary_file"], s["function_name"])


# ---------------------------------------------------------------------------
# Per-tool ran / hit logic
# ---------------------------------------------------------------------------

def cppcheck_ran(r: dict) -> bool:
    return not bool(r.get("error"))


def cppcheck_hit(r: dict, fstart: int, fend: int) -> bool:
    """Null-deref warning on a line inside the attacker's function."""
    for w in r.get("warnings_in_func", []):
        if not isinstance(w, list) or len(w) < 2:
            continue
        msg, line = w[0], w[1]
        id_match = re.search(r'\[(\w+)\]', msg)
        if id_match and id_match.group(1) not in CPPCHECK_NULL_IDS:
            continue
        if fstart <= line <= fend:
            return True
    return False


def infer_ran(r: dict) -> bool:
    return not bool(r.get("error"))


def infer_hit(r: dict, s: dict) -> bool:
    """
    Null-deref fires inside the function, OR fires in a direct caller.
    Only NULL_DEREFERENCE / NULLPTR_DEREFERENCE bug types count.
    """
    hits = r.get("hits", [])
    # Filter to null-deref types (infer JSON stores bug_type only if available)
    null_hits = [h for h in hits
                 if h.get("bug_type", "NULL_DEREFERENCE") in INFER_NULL_TYPES]

    if r.get("hit_in_function"):
        return True

    if not r.get("hit_anywhere") or not null_hits:
        return False

    fn   = s["function_name"]
    repo = Path(s["clone_dir"])
    for h in null_hits:
        hit_file = h.get("file", "")
        if not hit_file:
            continue
        for cf in list(repo.rglob(hit_file))[:1]:
            try:
                src = cf.read_text(errors="replace")
                if re.search(rf"\b{re.escape(fn)}\s*\(", src):
                    return True
            except OSError:
                pass
    return False


def codeql_ran(r: dict) -> bool:
    return not bool(r.get("error"))


def codeql_hit(r: dict, fstart: int, fend: int) -> bool:
    """Hit line (already filtered by NPD query) within the attacker's function."""
    for h in r.get("hits_in_file", []):
        if fstart <= h.get("line", 0) <= fend:
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    samples  = {s["slug"]: s for s in load_samples()}
    cppcheck = {r["slug"]: r for r in json.loads(CPPCHECK_IN.read_text())}
    infer    = {r["slug"]: r for r in json.loads(INFER_IN.read_text())}
    codeql   = {r["slug"]: r for r in json.loads(CODEQL_IN.read_text())}
    cls      = json.loads(CLASS_PATH.read_text())

    missing = [e["slug"] for e in cls if e["slug"] not in samples]
    if missing:
        print(f"[warn] {len(missing)} slugs not in samples: {missing[:5]}")

    for entry in cls:
        slug = entry["slug"]
        s    = samples.get(slug)
        if s is None:
            for tool in ("cppcheck", "infer", "codeql"):
                entry[f"{tool}_ran"] = False
                entry[f"{tool}_hit"] = False
            entry["any_sa_hit"] = False
            continue

        fstart, fend = _func_range(s)

        cp = cppcheck.get(slug, {})
        entry["cppcheck_ran"] = cppcheck_ran(cp)
        entry["cppcheck_hit"] = cppcheck_hit(cp, fstart, fend) if entry["cppcheck_ran"] else False

        inf = infer.get(slug, {})
        entry["infer_ran"] = infer_ran(inf)
        entry["infer_hit"] = infer_hit(inf, s) if entry["infer_ran"] else False

        cq = codeql.get(slug, {})
        entry["codeql_ran"] = codeql_ran(cq)
        entry["codeql_hit"] = codeql_hit(cq, fstart, fend) if entry["codeql_ran"] else False

        entry["any_sa_hit"] = entry["cppcheck_hit"] or entry["infer_hit"] or entry["codeql_hit"]

    CLASS_PATH.write_text(json.dumps(cls, indent=2))

    n = len(cls)
    print(f"{'Tool':<12} {'Coverage':>10}  {'Hit/ran':>12}  {'Hit/total':>12}")
    print("-" * 52)
    for tool in ("cppcheck", "infer", "codeql"):
        ran = sum(1 for e in cls if e.get(f"{tool}_ran"))
        hit = sum(1 for e in cls if e.get(f"{tool}_hit"))
        r_str = f"{hit}/{ran} ({100*hit/ran:.1f}%)" if ran else "—"
        t_str = f"{hit}/{n} ({100*hit/n:.1f}%)"
        print(f"{tool:<12} {ran:>5}/{n:<5}    {r_str:>12}  {t_str:>12}")

    any_hit = sum(1 for e in cls if e["any_sa_hit"])
    print(f"\nAny SA hit (of samples where all ran): ", end="")
    all_ran = sum(1 for e in cls if all(e.get(f"{t}_ran") for t in ("cppcheck","infer","codeql")))
    any_hit_all_ran = sum(1 for e in cls if e["any_sa_hit"] and all(e.get(f"{t}_ran") for t in ("cppcheck","infer","codeql")))
    print(f"{any_hit_all_ran}/{all_ran} ({100*any_hit_all_ran/all_ran:.1f}% recall-given-ran)")
    print(f"Any SA hit (all 128):               {any_hit}/{n} ({100*any_hit/n:.1f}%)")

    print("\nDetected:")
    for e in cls:
        if e["any_sa_hit"]:
            tools = [t for t in ("cppcheck", "infer", "codeql") if e[f"{t}_hit"]]
            print(f"  {e['slug']}: {tools}")
    print(f"\nResults → {CLASS_PATH}")


if __name__ == "__main__":
    main()
