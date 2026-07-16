from state.investigation import SOCInvestigationState

def run_report_generator(state: SOCInvestigationState) -> dict:
    """Report Generator agent node using MCP tools.

    Returns a partial update, same reasoning as agents/synthesis.py.
    """

    # Needs MCP tools: generateReport, logAuditEntry

    report = {
        "executive_summary": "Summary...",
        "evidence_chain": {},
        "attck_technique_cards": [],
        "confidence": state.get("confidence_score", 0.0),
        "uncertainty_flags": state.get("synthesis_output", {}).get("missing_evidence", []),
        "remediation_proposals": [{"action": "isolateHost", "requires_approval": True}]
    }

    return {
        "report_output": report,
        "agents_completed": ["report_generator"],
    }
