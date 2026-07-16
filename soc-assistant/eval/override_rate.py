from collections import defaultdict
from typing import Dict, Iterable


def calculate_override_rate(analyst_modifications: int, total_hitl_decisions: int) -> float:
    """
    Flat override rate across the whole pipeline.
    override_rate = analyst_modifications / total_hitl_decisions
    Kept for backward compatibility; prefer calculate_override_rate_by_role
    below, which attributes each modification to the upstream agent whose
    output the analyst actually corrected.
    """
    if total_hitl_decisions == 0:
        return 0.0
    return analyst_modifications / total_hitl_decisions


def calculate_override_rate_by_role(decisions: Iterable[dict]) -> Dict[str, float]:
    """
    Compute override rate attributed per upstream agent role.

    Each element of `decisions` is expected to look like:
        {
            "action": "approve" | "modify" | "reject" | "escalate",
            "corrected_fields": ["triage_output.severity", "attck_output.technique_ids", ...],
        }

    `corrected_fields` entries are dotted paths whose first segment maps to
    the state slot written by a given agent (see state/investigation.py):
        triage_output      -> "triage"
        log_output         -> "log_investigator"
        cti_output          -> "cti_enrichment"
        attck_output        -> "attck_mapper"
        synthesis_output    -> "reasoning_synthesis"
        report_output       -> "report_generator"

    Returns a dict of {agent_role: override_rate}, where override_rate is the
    fraction of decisions touching that role's output that were "modify" or
    "reject" (an "approve" or "escalate" with no corrected field for that
    role does not count against it).
    """
    field_to_role = {
        "triage_output": "triage",
        "log_output": "log_investigator",
        "cti_output": "cti_enrichment",
        "attck_output": "attck_mapper",
        "synthesis_output": "reasoning_synthesis",
        "report_output": "report_generator",
    }

    touched = defaultdict(int)
    overridden = defaultdict(int)

    for decision in decisions:
        action = decision.get("action")
        corrected_fields = decision.get("corrected_fields", [])
        roles_in_this_decision = set()
        for field in corrected_fields:
            prefix = field.split(".")[0]
            role = field_to_role.get(prefix)
            if role:
                roles_in_this_decision.add(role)

        for role in roles_in_this_decision:
            touched[role] += 1
            if action in ("modify", "reject"):
                overridden[role] += 1

    return {
        role: (overridden[role] / touched[role] if touched[role] else 0.0)
        for role in field_to_role.values()
        if touched[role] > 0
    }
