from state.investigation import SOCInvestigationState
from schemas.agent_io import LogInvestigatorOutput

def run_log_investigator(state: SOCInvestigationState) -> dict:
    """Log investigator agent node using MCP tools.

    Runs in parallel with cti_enrichment and attck_mapper (same LangGraph
    superstep). MUST return only the keys it touches -- returning the full
    state object here causes LangGraph's InvalidUpdateError the moment more
    than one parallel branch actually executes, because unrelated fields
    like alert_id would be "written" by every branch simultaneously.
    """
    output = LogInvestigatorOutput(
        events=[],
        entities={"ips": [], "users": [], "processes": []},
        timeline=[],
        anomalies=[] # e.g. cmd.exe spawned from WINWORD.EXE
    )

    return {
        "log_output": output.model_dump(),
        "agents_completed": ["log_investigator"],
    }
