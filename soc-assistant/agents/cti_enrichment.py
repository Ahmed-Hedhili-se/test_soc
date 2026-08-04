from state.investigation import SOCInvestigationState
from schemas.agent_io import CTIEnrichmentOutput
from mcp_tools.read_only.api import lookupIP
from mcp_tools.rag.api import retrieveCTIContext
from rag.store_ioc import get_ioc_exclusivity

def run_cti_enrichment(state: SOCInvestigationState) -> dict:
    """CTI Enrichment agent node using MCP tools.

    Runs in parallel with log_investigator and attck_mapper -- must return
    only the keys it touches (see agents/log_investigator.py for why). For
    the same reason it keys off alert_raw / alert_category only (both
    written before the parallel fan-out) and never log_output / attck_output,
    which are sibling branches in this same superstep and are not
    guaranteed to be populated yet.
    """
    alert_raw = state.get("alert_raw") or {}
    category  = state.get("alert_category")

    # -- IOC lookup (read-only MCP tool) ----------------------------------
    indicators: list[dict] = []
    for ip in filter(None, [alert_raw.get("source_ip"), alert_raw.get("dest_ip")]):
        rep = lookupIP(ip)
        exclusivity = get_ioc_exclusivity(ip)
        # Must discount confidence for shared infrastructure ("shared" exclusivity):
        # a CDN edge / corporate NAT gateway many benign hosts also share is
        # weaker evidence than a dedicated malicious host.
        confidence = rep.get("confidence", 0.0)
        if exclusivity == "shared":
            confidence = round(confidence * 0.5, 2)
        indicators.append({**rep, "exclusivity": exclusivity, "confidence": confidence})

    # -- RAG retrieval over CTI reports -----------------------------------
    keywords = [k for k in [alert_raw.get("process"), alert_raw.get("user")] if k]
    cti_context = retrieveCTIContext(category, keywords)

    output = CTIEnrichmentOutput(
        indicators=indicators,
        cti_context=cti_context,
    )

    return {
        "cti_output": output.model_dump(),
        "agents_completed": ["cti_enrichment"],
    }
