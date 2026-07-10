from state.investigation import SOCInvestigationState
from schemas.agent_io import LogInvestigatorOutput

def run_log_investigator(state: SOCInvestigationState) -> SOCInvestigationState:
    """Log investigator agent node using MCP tools."""
    
    output = LogInvestigatorOutput(
        events=[],
        entities={"ips": [], "users": [], "processes": []},
        timeline=[],
        anomalies=[] # e.g. cmd.exe spawned from WINWORD.EXE
    )
    
    state["log_output"] = output.model_dump()
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("log_investigator")
    
    return state
