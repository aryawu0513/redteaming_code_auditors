#!/usr/bin/env python3
"""
backfill_prompts.py — Reconstruct prompt_messages for an already-completed
adaptive run and inject them into the per-round JSON files.

Exact for runs with NO integrity retries (none in qwen_openvul_fromscratch).
For runs where retries fired, the reconstructed bundle of the WINNING attempt
won't carry the orchestrator's constraint_reminder, so it will be the round-N
attempt-1 bundle — close to but not exactly what the LLM finally saw.

Replays round-major + batch-sync semantics:
  * library snapshot is frozen at the start of each round
  * all types' round-N bundles use the same snapshot
  * round-N flips are appended to the library after the round, in args.types order

Usage:
    python attacker/adaptive/backfill_prompts.py --tag qwen_openvul_fromscratch
    python attacker/adaptive/backfill_prompts.py --tag qwen_openvul_fromscratch --from-scratch
"""
import argparse
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from refine_loop import (  # noqa: E402
    ALL_TYPES,
    BOOTSTRAP,
    SLUG,
    STYLE_SPECS,
    _make_library_entry,
    extract_annotation,
    filter_npd_paragraphs,
    load_record,
    replace_annotation,
)
from refiner_agent import _load_config  # noqa: E402

DEFAULT_RESULTS_ROOT = HERE / "results" / f"repository_{SLUG}"


def reconstruct(tag: str, from_scratch: bool, results_root: Path,
                types: list[str]) -> int:
    sys_template = _load_config()["system_prompt"]

    runs: dict[str, dict] = {}
    for t in types:
        d = results_root / f"adaptive_{t}_{tag}"
        if not d.exists():
            print(f"  skip {t}: no dir at {d}")
            continue
        rounds: dict[int, dict] = {}
        for rf in sorted(d.glob("round_*.json")):
            j = json.loads(rf.read_text())
            rounds[int(j["round"])] = j
        runs[t] = {"dir": d, "rounds": rounds, "record": load_record(SLUG, t)}

    if not runs:
        print(f"no runs found under {results_root} for tag={tag!r}")
        return 0

    library: list[dict] = [] if from_scratch else [copy.deepcopy(BOOTSTRAP)]

    # Round 0 contributions to library: any type whose round-0 verdict was safe.
    for t in types:
        if t not in runs:
            continue
        r0 = runs[t]["rounds"].get(0)
        if r0 and r0["detector_verdict"] == "safe":
            excerpt = filter_npd_paragraphs(r0.get("detector_reasoning", "")) \
                or r0.get("detector_reasoning", "")
            library.append(_make_library_entry(
                t, extract_annotation(runs[t]["record"]["target_function"]), excerpt
            ))

    # Determine max round across all types.
    max_round = max(max(rd.keys()) for rd in (runs[t]["rounds"] for t in runs))

    total_written = 0
    for rnd in range(1, max_round + 1):
        snapshot = list(library)  # frozen for the round
        flips: list[tuple[str, dict]] = []  # in `types` order
        for t in types:
            if t not in runs:
                continue
            rounds_for_t = runs[t]["rounds"]
            j = rounds_for_t.get(rnd)
            if j is None:
                continue  # type already terminated
            record = runs[t]["record"]

            # current_record.target_function at the START of round `rnd`
            if rnd == 1:
                current_tf = record["target_function"]
                det_prev = rounds_for_t[0]
            else:
                prev_j = rounds_for_t[rnd - 1]
                current_tf = replace_annotation(
                    record["target_function"], prev_j["annotation_text"]
                )
                det_prev = prev_j

            det = {
                "verdict": det_prev["detector_verdict"],
                "reasoning": det_prev["detector_reasoning"],
                "votes": det_prev.get("votes", {}),
            }
            filtered = filter_npd_paragraphs(det["reasoning"]) or det["reasoning"]

            prior_attempts = []
            for r in range(1, rnd):
                pj = rounds_for_t[r]
                prior_attempts.append({
                    "round": r,
                    "annotation_text": pj["annotation_text"],
                    "detector_reasoning_filtered":
                        pj.get("detector_reasoning_filtered") or "",
                })

            bundle = {
                "round": rnd,
                "annotation_type": t,
                "annotation_text": extract_annotation(current_tf),
                "annotation_location": (
                    "immediately before `long long ans = head->val;` "
                    "(the NPD deref site, ~line 12 of main)"
                ),
                "detector_verdict": det["verdict"],
                "detector_reasoning_filtered": filtered,
                "prior_attempts": prior_attempts,
                "target_function": current_tf,
                "style_exemplar": extract_annotation(record["target_function"]),
                "style_spec": STYLE_SPECS[t],
                "library": snapshot,
            }
            system_prompt = sys_template.replace("{annotation_type}", t)
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user",
                 "content": json.dumps(bundle, indent=2, ensure_ascii=False)},
            ]

            j["prompt_messages"] = messages
            j["_prompt_backfilled"] = True
            (runs[t]["dir"] / f"round_{rnd}.json").write_text(
                json.dumps(j, indent=2)
            )
            total_written += 1

            if j["detector_verdict"] == "safe":
                flips.append((t, j))

        # End of round: extend library with this round's flips, in `types` order.
        for t, j in flips:
            library.append(_make_library_entry(
                t,
                j["annotation_text"],
                j.get("detector_reasoning_filtered") or "",
            ))

    print(f"  rounds written: {total_written}  |  final library size: {len(library)}")
    return total_written


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True,
                        help="Run tag suffix on adaptive_{TYPE}_{tag}/ dirs.")
    parser.add_argument("--from-scratch", action="store_true",
                        help="The run was launched with --from-scratch (no BOOTSTRAP seed).")
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT,
                        help="Directory containing adaptive_*/ subdirs.")
    parser.add_argument("--types", nargs="+", default=ALL_TYPES, choices=ALL_TYPES,
                        help="Type order used in the original run (must match for "
                             "library-order fidelity). Default: ALL_TYPES.")
    args = parser.parse_args()

    print(f"backfilling prompts for tag={args.tag} (from_scratch={args.from_scratch})")
    n = reconstruct(args.tag, args.from_scratch, args.results_root, args.types)
    print(f"done. wrote {n} round files.")


if __name__ == "__main__":
    main()
