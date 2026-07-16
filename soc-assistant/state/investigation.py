import operator
from typing import TypedDict, Optional, Annotated
from datetime import datetime


def merge_dicts(left: dict, right: dict) -> dict:
    """Reducer for tool_calls_count: parallel agents each update their own
    per-agent counter key, so a shallow merge (not last-value-wins) is
    required when two branches write in the same superstep."""
    merged = dict(left or {})
    merged.update(right or {})
    return merged


class SOCInvestigationState(TypedDict):
    # Alert input
    alert_id: str
    alert_raw: dict
    alert_category: str
    alert_timestamp: str

    # Agent outputs — None until agent completes
    triage_output: Optional[dict]      # severity, fp_probability, category
    log_output: Optional[dict]         # correlated events, timeline
    cti_output: Optional[dict]         # enriched IOCs, threat context
    attck_output: Optional[dict]       # technique IDs, tactic chain

    # Pipeline control
    # NOTE: log_investigator / cti_enrichment / attck_mapper run as parallel
    # LangGraph branches in the same superstep. Any field more than one of
    # them can write to MUST use an Annotated reducer, or LangGraph raises
    # InvalidUpdateError ("Can receive only one value per step") the moment
    # more than one branch actually executes concurrently — this cannot be
    # caught by unit-testing agents in isolation, only by invoking the
    # compiled graph end to end (see tests/test_orchestrator_graph.py).
    agents_activated: Annotated[list[str], operator.add]
    agents_completed: Annotated[list[str], operator.add]
    agents_failed: Annotated[list[str], operator.add]
    tool_calls_count: Annotated[dict[str, int], merge_dicts]   # budget tracking per agent
    missing_evidence: Annotated[list[str], operator.add]

    # Synthesis + report
    synthesis_output: Optional[dict]   # verdict, confidence, narrative
    report_output: Optional[dict]      # formatted incident report

    # HITL
    confidence_score: float
    escalation_flag: bool
    hitl_decision: Optional[str]       # approve | modify | reject | escalate
    analyst_note: Optional[str]
    approved_by: Optional[str]         # populated only by HITL interface

    # Audit
    audit_log: Annotated[list[dict], operator.add]
    pipeline_start_time: str
    pipeline_end_time: Optional[str]
