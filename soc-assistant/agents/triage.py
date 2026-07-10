from state.investigation import SOCInvestigationState
from schemas.alert import NormalizedAlert
from schemas.agent_io import TriageOutput
from typing import Dict, Any

def run_triage_agent(state: SOCInvestigationState) -> SOCInvestigationState:
    """Triage agent node using MCP tools."""
    # Stub: checkMaintenanceWindow should be checked before final severity is computed
    # Stub: Tool budget check 
    
    # Example typed output mapping
    output = TriageOutput(
        severity=7.5,
        fp_probability=0.2,
        category=state.get("alert_category", "other"),
        authorized_activity=False
    )
    
    state["triage_output"] = output.model_dump()
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("triage")
    
    return state
