from state.investigation import SOCInvestigationState
from schemas.agent_io import ATTCKMapperOutput

def run_attck_mapper(state: SOCInvestigationState) -> dict:
    """ATT&CK Mapper agent node using MCP tools.

    Runs in parallel with log_investigator and cti_enrichment -- must
    return only the keys it touches (see agents/log_investigator.py for why).
    """
    output = ATTCKMapperOutput(
        technique_ids=[],
        kill_chain_position=0,
        observed_tactics=[],
        predicted_next=[]
    )

    return {
        "attck_output": output.model_dump(),
        "agents_completed": ["attck_mapper"],
    }
