from state.investigation import SOCInvestigationState
from schemas.agent_io import ATTCKMapperOutput
from mcp_tools.rag.api import (
    techniquesForCategory,
    getTechniqueDetail,
    buildTacticChain,
    killChainPosition,
    predictNextTactics,
)

def run_attck_mapper(state: SOCInvestigationState) -> dict:
    """ATT&CK Mapper agent node using MCP tools.

    Runs in parallel with log_investigator and cti_enrichment -- must
    return only the keys it touches (see agents/log_investigator.py for
    why). Keys off alert_category / triage_output only, both written
    before the parallel fan-out; log_output and cti_output are sibling
    branches in this same superstep and are not guaranteed to be
    populated yet.
    """
    category = state.get("alert_category") or (state.get("triage_output") or {}).get("category")

    candidates    = techniquesForCategory(category)
    technique_ids = [t["id"] for t in candidates]

    # Per-technique enrichment via the RAG knowledge base (falls back to
    # the built-in table entry itself when the Chroma store isn't
    # indexed/available).
    technique_details = [getTechniqueDetail(tid) for tid in technique_ids]

    observed_tactics = buildTacticChain(technique_ids)
    predicted_next    = predictNextTactics(observed_tactics)

    output = ATTCKMapperOutput(
        technique_ids=technique_ids,
        kill_chain_position=killChainPosition(observed_tactics),
        observed_tactics=observed_tactics,
        predicted_next=predicted_next,
        technique_details=technique_details,
    )

    return {
        "attck_output": output.model_dump(),
        "agents_completed": ["attck_mapper"],
    }
