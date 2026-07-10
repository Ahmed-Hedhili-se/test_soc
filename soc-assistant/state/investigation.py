from typing import TypedDict, Optional
from datetime import datetime

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
    agents_activated: list[str]
    agents_completed: list[str]
    agents_failed: list[str]
    tool_calls_count: dict[str, int]   # budget tracking per agent

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
    audit_log: list[dict]
    pipeline_start_time: str
    pipeline_end_time: Optional[str]
