"""
review/feedback/preference_pairs.py

DPO preference-pair capture -- the second, separate branch of the analyst
feedback loop.

update_rag_from_correction() (see rag_update.py) refreshes the RAG
knowledge base's document corpus (fast, cheap, append-only). This module
captures a different signal: (prompt, chosen, rejected) triples, one per
agent role, used to DPO fine-tune that role's model (slow, batched, gated
on eval -- see training/dpo_train.py). The two loops are triggered
together from hitl/api.py but write to separate stores and run on
different cadences.

A pair is only emitted for a role when the analyst's decision actually
changed that role's output (state[<role_output_key>] differs before vs.
after applying modified_fields). A bare "reject" with no replacement
value tells us the original output was wrong but not what "right" looks
like, so it cannot be turned into a (chosen, rejected) pair -- it still
feeds the RAG correction ledger, just not this one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

# Built from this file's own location, same convention as rag_update.py,
# so it resolves correctly regardless of the caller's current working
# directory.
_PAIRS_DIR = Path(__file__).resolve().parents[2] / "data" / "dpo_pairs"

# state output key -> agent role name. Mirrors eval/override_rate.py's
# field_to_role table and the real data-dependency topology documented in
# orchestrator/graph.py.
ROLE_OUTPUT_KEYS: dict[str, str] = {
    "triage_output":    "triage",
    "log_output":       "log_investigator",
    "cti_output":        "cti_enrichment",
    "attck_output":       "attck_mapper",
    "synthesis_output":   "reasoning_synthesis",
    "report_output":      "report_generator",
}


def build_prompt_context(role: str, state: dict) -> dict:
    """
    Return the slice of *state* that was actually available as input to
    *role* at the point it ran -- matching the graph's real data
    dependencies (see orchestrator/graph.py):
      - triage runs first and sees only the raw alert.
      - log_investigator / cti_enrichment / attck_mapper run in the SAME
        parallel superstep -- each may see triage_output but never each
        other's outputs.
      - reasoning_synthesis runs after the fan-in and sees all four.
      - report_generator runs last and sees the synthesis output.
    Always pass the PRE-decision state snapshot here, since the analyst's
    edit must not leak into what we claim the agent "saw".
    """
    alert_ctx = {
        "alert_id":       state.get("alert_id"),
        "alert_raw":      state.get("alert_raw"),
        "alert_category": state.get("alert_category"),
    }

    if role in ("triage", "log_investigator", "cti_enrichment"):
        return alert_ctx
    if role == "attck_mapper":
        return {**alert_ctx, "triage_output": state.get("triage_output")}
    if role == "reasoning_synthesis":
        return {
            **alert_ctx,
            "triage_output": state.get("triage_output"),
            "log_output":    state.get("log_output"),
            "cti_output":    state.get("cti_output"),
            "attck_output":  state.get("attck_output"),
        }
    if role == "report_generator":
        return {
            **alert_ctx,
            "synthesis_output": state.get("synthesis_output"),
            "confidence_score":  state.get("confidence_score"),
        }
    return alert_ctx


def build_preference_pair(
    role: str,
    prompt_context: dict,
    rejected_output: dict,
    chosen_output: dict,
    *,
    investigation_id: str,
    analyst_id: str,
    analyst_note: Optional[str],
    action: str,
    timestamp: str,
) -> dict:
    """Assemble one DPO-ready preference pair record for *role*."""
    return {
        "role":             role,
        "investigation_id": investigation_id,
        "analyst_id":       analyst_id,
        "action":           action,
        "analyst_note":     analyst_note,
        "timestamp":        timestamp,
        "prompt":           prompt_context,
        "chosen":           chosen_output,
        "rejected":         rejected_output,
    }


def _pairs_path(role: str) -> Path:
    return _PAIRS_DIR / f"{role}.jsonl"


def append_preference_pair(pair: dict) -> Path:
    """Append *pair* to its role's JSONL preference dataset."""
    path = _pairs_path(pair["role"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(pair) + "\n")
    return path


def load_preference_pairs(role: str) -> list[dict]:
    """Load all persisted preference pairs for *role*."""
    path = _pairs_path(role)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def count_preference_pairs(role: str) -> int:
    return len(load_preference_pairs(role))


def record_preference_pairs_from_decision(
    before_state: dict,
    after_state: dict,
    *,
    investigation_id: str,
    analyst_id: str,
    action: str,
    note: Optional[str],
    timestamp: str,
) -> list[dict]:
    """
    Diff *before_state* / *after_state* across every agent role's output
    slot and persist a DPO preference pair for each one the analyst
    actually changed. Returns the pairs written (empty if the decision
    didn't replace any role's output -- e.g. a plain "reject").
    """
    written: list[dict] = []
    for output_key, role in ROLE_OUTPUT_KEYS.items():
        before_output = before_state.get(output_key)
        after_output  = after_state.get(output_key)
        if before_output is None or after_output is None:
            continue
        if before_output == after_output:
            continue

        pair = build_preference_pair(
            role=role,
            prompt_context=build_prompt_context(role, before_state),
            rejected_output=before_output,
            chosen_output=after_output,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            analyst_note=note,
            action=action,
            timestamp=timestamp,
        )
        append_preference_pair(pair)
        written.append(pair)
    return written
