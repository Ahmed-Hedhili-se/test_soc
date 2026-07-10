from state.investigation import SOCInvestigationState
from schemas.agent_io import ATTCKMapperOutput

def run_attck_mapper(state: SOCInvestigationState) -> SOCInvestigationState:
    """ATT&CK Mapper agent node using MCP tools."""
    
    output = ATTCKMapperOutput(
        technique_ids=[],
        kill_chain_position=0,
        observed_tactics=[],
        predicted_next=[]
    )
    
    state["attck_output"] = output.model_dump()
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("attck_mapper")
    
    return state
