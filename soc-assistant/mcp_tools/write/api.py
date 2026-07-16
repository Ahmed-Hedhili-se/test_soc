"""
mcp_tools/write/api.py

Write-tool MCP implementations. These are the ONLY tools that change the
real environment (isolateHost, disableUserAccount, blockIPFirewall,
createTicket). Every one of them is gated on `approved_by`, which per the
architecture is populated exclusively by hitl/api.py's decision endpoint.

Bugs fixed relative to the original version:
  - WriteActionInput was missing `alert_id`, so callers that supplied it
    (e.g. tests/test_pipeline.py) had it silently dropped by pydantic's
    default "ignore extra fields" behavior rather than stored/returned.
  - Every write tool returned None (a bare `pass` after the approval
    check), so any caller expecting a result (status, audit trail) would
    hit a TypeError trying to subscript it. Each tool now returns a small
    "simulated" result dict and logs an audit entry, matching what a real
    write action would report back to the HITL layer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel
from fastapi import HTTPException


class WriteActionInput(BaseModel):
    approved_by: str
    target: str
    justification: str
    alert_id: Optional[str] = None


def validate_approval(input_data: WriteActionInput) -> None:
    if not input_data.approved_by:
        raise HTTPException(
            status_code=403,
            detail="approved_by field is required for write actions. Must be populated by HITL interface.",
        )


def _simulated_result(action: str, input_data: WriteActionInput) -> dict:
    """Shared result shape for every write tool; also emits an audit entry."""
    from mcp_tools.read_only.api import logAuditEntry

    result = {
        "status": "simulated",
        "action": action,
        "target": input_data.target,
        "approved_by": input_data.approved_by,
        "justification": input_data.justification,
        "alert_id": input_data.alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    logAuditEntry({"tool": action, **result})
    return result


def isolateHost(input_data: WriteActionInput) -> dict:
    validate_approval(input_data)
    return _simulated_result("isolateHost", input_data)


def disableUserAccount(input_data: WriteActionInput) -> dict:
    validate_approval(input_data)
    return _simulated_result("disableUserAccount", input_data)


def blockIPFirewall(input_data: WriteActionInput) -> dict:
    validate_approval(input_data)
    return _simulated_result("blockIPFirewall", input_data)


def createTicket(input_data: WriteActionInput) -> dict:
    validate_approval(input_data)
    return _simulated_result("createTicket", input_data)
