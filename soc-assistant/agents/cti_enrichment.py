from state.investigation import SOCInvestigationState
from schemas.agent_io import CTIEnrichmentOutput

def run_cti_enrichment(state: SOCInvestigationState) -> dict:
    """CTI Enrichment agent node using MCP tools.

    Runs in parallel with log_investigator and attck_mapper -- must return
    only the keys it touches (see agents/log_investigator.py for why).
    """
    # Must discount confidence for shared infrastructure ("shared" exclusivity)

    output = CTIEnrichmentOutput(
        indicators=[]
    )

    return {
        "cti_output": output.model_dump(),
        "agents_completed": ["cti_enrichment"],
    }
