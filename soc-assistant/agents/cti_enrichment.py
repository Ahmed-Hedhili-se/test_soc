from state.investigation import SOCInvestigationState
from schemas.agent_io import CTIEnrichmentOutput

def run_cti_enrichment(state: SOCInvestigationState) -> SOCInvestigationState:
    """CTI Enrichment agent node using MCP tools."""
    
    # Must discount confidence for shared infrastructure ("shared" exclusivity)
    
    output = CTIEnrichmentOutput(
        indicators=[]
    )
    
    state["cti_output"] = output.model_dump()
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("cti_enrichment")
    
    return state
