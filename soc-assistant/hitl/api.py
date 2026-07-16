"""
hitl/api.py

Human-in-the-Loop FastAPI backend.

Endpoints:
  GET  /investigations/                -- list all active investigations
  GET  /investigations/{id}            -- retrieve investigation evidence before verdict
  GET  /investigations/{id}/reasoning-trace -- full synthesis reasoning trace
  GET  /investigations/{id}/report     -- return full incident report
  POST /investigations/{id}/decision   -- analyst decision (only path that can populate approved_by)
  GET  /metrics/override-rate          -- retrieve per-agent override rates
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from review.feedback.rag_update import update_rag_from_correction
from eval.override_rate import calculate_override_rate_by_role

app = FastAPI(
    title="SOC Assistant HITL API",
    description=(
        "Human-in-the-Loop validation interface for the Agentic SOC Assistant. "
        "The POST /decision endpoint is the ONLY code path permitted to set `approved_by`."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# In-memory investigation store (shared with the pipeline)
# ---------------------------------------------------------------------------
_investigation_store: Dict[str, Dict[str, Any]] = {}
_decision_log: List[dict] = []


def register_investigation(alert_id: str, state: Dict[str, Any]) -> None:
    """Called by the pipeline runner to register a completed investigation."""
    _investigation_store[alert_id] = state


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class HITLDecision(BaseModel):
    action: str                              # approve | modify | reject | escalate
    analyst_id: str
    modified_fields: Optional[Dict[str, Any]] = None
    corrected_fields: Optional[List[str]]     = None  # for override rate tracking
    note: Optional[str]                       = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/investigations/", response_model=List[str])
async def list_investigations():
    """List all registered investigation IDs."""
    return list(_investigation_store.keys())


@app.get("/investigations/{id}")
async def get_investigation_evidence(id: str):
    """
    Returns the evidence chain for a given investigation -- triage, logs,
    CTI, ATT&CK output -- for analyst review BEFORE the verdict is acted upon.
    """
    state = _investigation_store.get(id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Investigation '{id}' not found.")

    return {
        "alert_id":     state.get("alert_id"),
        "alert_raw":    state.get("alert_raw"),
        "triage_output":state.get("triage_output"),
        "log_output":   state.get("log_output"),
        "cti_output":   state.get("cti_output"),
        "attck_output": state.get("attck_output"),
        "sla_deadline":  datetime.now(timezone.utc).isoformat(),  # placeholder
        "agents_completed": state.get("agents_completed", []),
    }


@app.get("/investigations/{id}/reasoning-trace")
async def get_reasoning_trace(id: str):
    """Full synthesis reasoning trace -- narrative, confidence, escalation."""
    state = _investigation_store.get(id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Investigation '{id}' not found.")

    return {
        "synthesis_output": state.get("synthesis_output"),
        "confidence_score": state.get("confidence_score"),
        "escalation_flag":  state.get("escalation_flag"),
        "missing_evidence": state.get("missing_evidence", []),
    }


@app.get("/investigations/{id}/report")
async def get_report(id: str):
    """Return the full formatted incident report."""
    state = _investigation_store.get(id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Investigation '{id}' not found.")
    return state.get("report_output", {})


@app.post("/investigations/{id}/decision")
async def receive_decision(id: str, decision: HITLDecision):
    """
    Receives the analyst's decision.  This is the ONLY endpoint that is
    permitted to set `approved_by` on the investigation state.

    - approve  -> set approved_by, forward to write MCP tools (simulated)
    - modify   -> update state fields, trigger RAG update
    - reject   -> mark as false positive, trigger RAG update
    - escalate -> flag for senior analyst review
    """
    state = _investigation_store.get(id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Investigation '{id}' not found.")

    action     = decision.action.lower()
    analyst_id = decision.analyst_id
    timestamp  = datetime.now(timezone.utc).isoformat()

    if action not in ("approve", "modify", "reject", "escalate"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{action}'. Must be one of: approve, modify, reject, escalate.",
        )

    # Record the decision in the log
    log_entry = {
        "investigation_id": id,
        "action":           action,
        "analyst_id":       analyst_id,
        "timestamp":        timestamp,
        "corrected_fields": decision.corrected_fields or [],
        "note":             decision.note,
    }
    _decision_log.append(log_entry)

    # -- Process decision --------------------------------------------------
    response_extra: dict = {}

    if action == "approve":
        # Set approved_by -- the ONLY place this field is ever written
        state["approved_by"]   = analyst_id
        state["hitl_decision"] = "approve"
        response_extra["approved_by"] = analyst_id
        response_extra["message"] = (
            "Investigation approved. Remediation proposals may now be executed "
            "via the write MCP tools using the approved_by token."
        )

    elif action in ("modify", "reject"):
        state["hitl_decision"] = action
        state["analyst_note"]  = decision.note

        if decision.modified_fields:
            for field, value in decision.modified_fields.items():
                if field != "approved_by":  # approved_by can ONLY be set via approve
                    state[field] = value

        # Trigger RAG feedback loop
        update_rag_from_correction({
            "investigation_id": id,
            "action":           action,
            "corrected_fields": decision.corrected_fields or [],
            "analyst_note":     decision.note,
            "original_verdict": state.get("synthesis_output", {}).get("verdict"),
            "timestamp":        timestamp,
        })
        response_extra["message"] = (
            "Decision recorded and RAG feedback loop triggered."
        )

    elif action == "escalate":
        state["hitl_decision"] = "escalate"
        state["escalation_flag"] = True
        state["analyst_note"]  = decision.note
        response_extra["message"] = "Investigation escalated for senior analyst review."

    # Persist updated state
    _investigation_store[id] = state

    return {
        "status":           "decision_recorded",
        "action":           action,
        "investigation_id": id,
        "analyst_id":       analyst_id,
        "timestamp":        timestamp,
        **response_extra,
    }


@app.get("/metrics/override-rate")
async def get_override_rate():
    """Return per-agent override rates from the HITL decision log."""
    rates = calculate_override_rate_by_role(_decision_log)
    return {
        "override_rates_by_agent": rates,
        "total_decisions":         len(_decision_log),
        "computed_at":             datetime.now(timezone.utc).isoformat(),
    }
