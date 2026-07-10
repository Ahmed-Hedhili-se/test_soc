from state.investigation import SOCInvestigationState

def run_report_generator(state: SOCInvestigationState) -> SOCInvestigationState:
    """Report Generator agent node using MCP tools."""
    
    # Needs MCP tools: generateReport, logAuditEntry
    
    report = {
        "executive_summary": "Summary...",
        "evidence_chain": {},
        "attck_technique_cards": [],
        "confidence": state.get("confidence_score", 0.0),
        "uncertainty_flags": state.get("synthesis_output", {}).get("missing_evidence", []),
        "remediation_proposals": [{"action": "isolateHost", "requires_approval": True}]
    }
    
    state["report_output"] = report
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("report_generator")
    
    return state
