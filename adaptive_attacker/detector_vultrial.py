"""
detector_vultrial.py — VulTrial wrapper with OpenVulDetector-like interface.
"""
from __future__ import annotations

import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from VulTrial.run import run_evaluation

VULTRIAL_DIR = Path(__file__).parent.parent / "VulTrial"


class _Args:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class VulTrialDetector:
    """
    Runs VulTrial on a one-record dataset dir.
    Verdict: vulnerable if predicted_is_vulnerable == "yes".
    Reasoning: raw output text from VulTrial.
    """

    def __init__(self, model: str = "gpt-4o", mode: str = "npd",
                 max_workers: int | None = None,
                 defense_text: str | None = None,
                 screening_variant: str | None = None,
                 steering: str | None = None,
                 baseline_source: tuple[str, str] | None = None) -> None:
        self.model = model
        self.mode = mode
        self.defense_text = defense_text  # comment-trust policy appended to agent prompts
        self.screening_variant = screening_variant  # "labeled" (D3) or "D4" — prescreen target_function
        self.steering = steering  # "baseline" (D5) — prepend the detector's own clean-code verdict
        self.baseline_source = baseline_source  # (system, tag) — verify+reuse D0's own cached gate reasoning
        self._baseline_cache: dict[str, str] = {}  # sha256(clean_target_function) -> reasoning
        self.thread_safe = True  # OpenAI API calls; no shared engine state
        # None = unbounded (one thread per record, current behavior). Set an int
        # to cap concurrent gpt-4o subprocesses if a caller sends large batches.
        self._max_workers = max_workers

    def _run_trial(self, target_function: str, record: dict, defense) -> dict:
        """One VulTrial multi-agent trial on `target_function`. `defense` is
        either a plain string (applied identically to Security-Researcher/
        Moderator/Review-Board, VulTrial's original behavior) or a dict of
        per-role text (see _build_per_role_anchor). Returns the raw
        {"verdict", "reasoning", "votes", "id_save"} dict — no
        screening/steering applied here, callers layer those on top.
        `id_save` lets a caller locate this trial's full multi-agent
        transcript at VulTrial/results/all_record/{id_save}.txt afterward."""
        with tempfile.TemporaryDirectory(prefix="vultrial_det_") as tmp:
            ds_dir = Path(tmp) / "dataset"
            ds_dir.mkdir(parents=True, exist_ok=True)
            # Name file so VulTrial parses attack type cleanly.
            # VulTrial caches results keyed on slug+attack — callers must set
            # record["variant"] to a unique value per round to avoid cache hits.
            slug = record.get("slug") or "record"
            attack = record.get("variant") or "CLEAN"
            vultrial_record = {
                **record,
                "code":   target_function,
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
                defense=defense,
            )
            # Mirrors run_evaluation's own id_save formula exactly (run.py
            # line ~298) so we can find this trial's all_record transcript
            # afterward without VulTrial having to hand it back to us.
            model_slug = self.model.replace("-", "_").replace(".", "_")
            id_save = f"{slug}_{attack}_{self.mode}_{model_slug}"

            results = run_evaluation(args)

            # Capture per-turn text NOW, immediately after this trial writes
            # it — VulTrial's id_save has no run-tag/defense component, so
            # results/output/{id_save}/{0-3}.txt is a shared, overwrite-mode
            # namespace: the next D1/D2/D5 portfolio run touching the same
            # slug+attack_type+round silently clobbers it. Reading it here,
            # synchronously, before returning control to the caller, and
            # persisting it into OUR OWN scoped round_N.json (see
            # refine_loop_fromscratch.py) is the only way to make this data
            # durable — confirmed necessary: retrospective reads of these
            # files for old runs turned out ~53% contaminated (different
            # decision text than what was actually generated at the time).
            per_turn = None
            turn_dir = VULTRIAL_DIR / "results" / "output" / id_save
            if all((turn_dir / f"{t}.txt").exists() for t in (0, 1, 2, 3)):
                per_turn = {role: (turn_dir / f"{turn}.txt").read_text().strip()
                            for role, turn in self._ROLE_TURN_FILE.items()}

            if not results:
                out = {"verdict": "safe", "reasoning": "VulTrial produced no results.",
                       "votes": {"has_vul": 0, "no_vul": 1}, "id_save": id_save}
                if per_turn:
                    out["per_turn"] = per_turn
                return out
            r = results[0]
            predicted = r.get("predicted_is_vulnerable", "")
            if predicted == "yes":
                verdict = "vulnerable"
            elif predicted in ("no",):
                verdict = "safe"
            else:
                verdict = "error"  # unknown = subprocess/parse failure, not a clean safe
            reasoning = r.get("output", "")
            votes = ({"has_vul": 1, "no_vul": 0} if verdict == "vulnerable"
                     else {"has_vul": 0, "no_vul": 1} if verdict == "safe"
                     else {"has_vul": 0, "no_vul": 0})
            out = {"verdict": verdict, "reasoning": reasoning, "votes": votes, "id_save": id_save}
            if per_turn:
                out["per_turn"] = per_turn
            return out

    # JudgeOrder's turn order (agentverse/environments/simulation_env/rules/
    # order/judge.py) is a FIXED, NON-REPEATING single pass with max_turns=4:
    # security_researcher -> code_author -> moderator -> review_board, one
    # turn each, no revision loop. judge.py's print_messages() writes each
    # turn's raw message to results/output/{id_save}/{cnt_turn}.txt in WRITE
    # mode (fresh every call) BEFORE incrementing cnt_turn, so turn N's file
    # is written using cnt_turn=N (0-indexed) — giving this fixed mapping.
    # (Do NOT use results/all_record/{id_save}.txt for this: it's opened in
    # APPEND mode and id_save has no run-tag/defense component, so it
    # silently accumulates every historical call ever made for the same
    # slug+attack+round — confirmed directly: some entries there contain 3-4
    # concatenated passes from unrelated past sessions, easy to misread as
    # in-call revision that never actually happens.)
    _ROLE_TURN_FILE = {"security_researcher": 0, "code_author": 1,
                        "moderator": 2, "review_board": 3}

    def _get_baseline_per_role(self, clean_tf: str, record: dict) -> dict[str, str]:
        """D5: EACH defended role's OWN verdict/reasoning on the clean,
        comment-free function. Three sources, in order:

        1. **Persisted, safely-scoped cache** — self.baseline_source's own
           adaptive_attacker/results/{system}/repository_{slug}/
           baseline_per_role_{tag}.json, if present. This is a one-time
           verified export (see scratchpad/persist_vultrial_baseline_per_role.py)
           of source 2 below, made exactly because source 2 is fragile — read
           this first so a normal run never touches VulTrial's shared
           namespace at all.

        2. **D0's own live gate call, cross-verified** — every
           vultrial_full-family baseline gate check already runs this exact
           4-agent trial (record["variant"] defaults to "CLEAN" when unset,
           matching load_baseline_record's bare CLEAN.json load), so its
           per-role turns already exist at
           results/output/{slug}_CLEAN_{mode}_{model_slug}/{0,1,2,3}.txt —
           but that path is a shared, unscoped, overwrite-mode global
           namespace (VulTrial's own id_save has no run-tag/defense
           component), so ANY other VulTrial-based run's own non-fully-seeded
           gate check on the same slug can silently overwrite it with
           DEFENDED reasoning. Verify the review_board turn there matches
           self.baseline_source's safely-scoped baseline_gate_{tag}.json
           reasoning before trusting any of it.

        3. **Fresh, uniquely-tagged ("_baseline" suffix) undefended trial** —
           last resort if neither of the above is available."""
        import hashlib
        key = hashlib.sha256(clean_tf.encode()).hexdigest()[:16]
        if key in self._baseline_cache:
            return self._baseline_cache[key]

        slug = record.get("slug") or "record"

        if self.baseline_source:
            system, tag = self.baseline_source
            persisted_path = (Path(__file__).parent / "results" / system
                               / f"repository_{slug}" / f"baseline_per_role_{tag}.json")
            if persisted_path.exists():
                import json
                out = json.loads(persisted_path.read_text())["per_role"]
                self._baseline_cache[key] = out
                return out

        model_slug = self.model.replace("-", "_").replace(".", "_")
        d0_out_dir = VULTRIAL_DIR / "results" / "output" / f"{slug}_CLEAN_{self.mode}_{model_slug}"
        verified = False
        if self.baseline_source and (d0_out_dir / "3.txt").exists():
            system, tag = self.baseline_source
            gate_path = (Path(__file__).parent / "results" / system
                         / f"repository_{slug}" / f"baseline_gate_{tag}.json")
            if gate_path.exists():
                import json
                bg = json.loads(gate_path.read_text())
                shared_review_board = (d0_out_dir / "3.txt").read_text().strip()
                verified = bg.get("verdict") == "vulnerable" and bg.get("reasoning", "").strip() == shared_review_board

        if verified and all((d0_out_dir / f"{t}.txt").exists() for t in self._ROLE_TURN_FILE.values()):
            out = {role: (d0_out_dir / f"{turn}.txt").read_text().strip()
                   for role, turn in self._ROLE_TURN_FILE.items()}
            self._baseline_cache[key] = out
            return out

        clean_record = {**record, "variant": f"{record.get('variant', 'record')}_baseline"}
        clean_record.pop("clean_target_function", None)
        result = self._run_trial(clean_tf, clean_record, defense="")
        out_dir = VULTRIAL_DIR / "results" / "output" / result["id_save"]
        fallback = result["reasoning"] or "(no baseline output)"
        out = {}
        for role, turn in self._ROLE_TURN_FILE.items():
            f = out_dir / f"{turn}.txt"
            # Fall back to the final (review_board) verdict for any role that
            # never got a turn (e.g. SR-suppressed trial cut the debate short).
            out[role] = f.read_text().strip() if f.exists() else fallback
        self._baseline_cache[key] = out
        return out

    def _build_per_role_anchor(self, clean_tf: str, record: dict) -> dict[str, str]:
        """Same ordering as OpenVul/VulnLLM-R's D5 (detector_openvul.py
        _build_prompt): [Prior Analysis block] THEN [defense_text], so
        defense_text's own "Below the code, after it, you are given a
        [Prior Analysis] block..." wording reads naturally. defense_text
        (D5B_COT, from registry.py) is used VERBATIM — same wording as the
        other two detectors, no VulTrial-specific additions."""
        base = self._get_baseline_per_role(clean_tf, record)
        out = {}
        for role, own_prior in base.items():
            anchor = (f"[Prior Analysis — before any comments were present]\n"
                      f"{own_prior}\n[End Prior Analysis]")
            out[role] = (anchor + "\n\n" + self.defense_text.strip()) if self.defense_text else anchor
        return out

    def detect(self, record: dict) -> dict:
        # VulTrial reads `code`, `target`, `idx` from the record JSON.
        # Send only the target_function — VulTrial is designed for focused snippets.
        tf = record.get("target_function", "")
        screening_block = None
        if self.screening_variant:
            from defenses.screening_cache import get_or_screen
            screened = get_or_screen(tf)
            key = "d4_code" if self.screening_variant == "D4" else "d3_code"
            tf = screened[key]
            screening_block = {k: v for k, v in screened.items() if k not in ("d3_code", "d4_code")}

        # D5 (baseline-steered): build a PER-ROLE Prior Analysis anchor — each
        # of security_researcher/moderator/review_board sees only ITS OWN
        # prior turn from the undefended baseline trial, not one shared block
        # (VulTrial/run.py's _build_prompts now accepts a per-role dict).
        if self.steering == "baseline":
            clean_tf = record.get("clean_target_function", "")
            if clean_tf:
                defense = self._build_per_role_anchor(clean_tf, record)
            else:
                defense = self.defense_text or ""
        else:
            defense = self.defense_text or ""

        result = self._run_trial(tf, record, defense=defense)
        result["screening_block"] = screening_block
        return result

    def detect_batch(self, records: list[dict]) -> list[dict]:
        if not records:
            return []
        workers = len(records) if self._max_workers is None \
            else min(len(records), self._max_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(self.detect, records))
