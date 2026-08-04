"""
agents/cti_enrichment.py

CTI Enrichment agent -- runs in parallel with log_investigator and attck_mapper.

Pre-fetches deterministic context via MCP read-only tools and the RAG
knowledge base, then calls the configured LLM (see config/provider.py) to
reason over it. If the LLM's parsed response omits `indicators` (e.g.
SOC_ASSISTANT_MOCK_LLM=1, or a malformed completion), the pre-fetched,
RAG/IOC-derived indicators are used directly instead -- this agent always
returns something useful even with no live model behind it.
"""
from __future__ import annotations

import re

from langchain_core.messages import SystemMessage, HumanMessage

from config.provider import get_provider
from state.investigation import SOCInvestigationState
from schemas.agent_io import CTIEnrichmentOutput
from mcp_tools.read_only.api import lookupIP, lookupHash
from mcp_tools.rag.api import retrieveCTIContext
from rag.store_ioc import get_ioc_exclusivity


_SYSTEM_PROMPT = """You are an expert Cyber Threat Intelligence (CTI) Analyst. Your job is to analyze a security alert and enrich any indicators of compromise (IOCs) found, such as:
- IP addresses: Assess reputation (malicious/suspicious/clean), known threat actor or campaign.
- Domains/URLs: Assess if known C2, phishing, or malware distribution.
- File hashes: Assess if known malware.
- Techniques: Map to known threat groups or campaigns.

You MUST respond with ONLY a valid JSON object in this exact format, no explanations:
{
  "indicators": [
    {
      "type": "<ip|domain|hash|technique>",
      "value": "<indicator value>",
      "reputation": "<malicious|suspicious|clean|unknown>",
      "threat_actor": "<actor name or null>",
      "campaign": "<campaign name or null>",
      "confidence": <float 0.0-1.0>
    }
  ],
  "cti_confidence": <float 0.0-1.0>,
  "threat_summary": "<brief threat context>"
}"""


def _prefetch_ioc_indicators(alert_raw: dict) -> list[dict]:
    """
    Deterministic IOC lookup via MCP read-only tools: source_ip/dest_ip
    fields plus any IPs/hashes found in the raw log text. Discounts
    confidence for infrastructure recorded as `shared` in the IOC store
    (rag/store_ioc.py) -- a CDN edge / corporate NAT gateway many benign
    hosts also share is weaker evidence than a dedicated malicious host.
    """
    raw_log = alert_raw.get("raw_log", "") or ""
    ips = {alert_raw.get("source_ip"), alert_raw.get("dest_ip")} | set(
        re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw_log)
    )
    ips.discard(None)

    indicators: list[dict] = []
    for ip in ips:
        rep = lookupIP(ip)
        exclusivity = get_ioc_exclusivity(ip)
        confidence = rep.get("confidence", 0.0)
        if exclusivity == "shared":
            confidence = round(confidence * 0.5, 2)
        indicators.append({**rep, "exclusivity": exclusivity, "confidence": confidence})

    for file_hash in set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", raw_log)):
        indicators.append(lookupHash(file_hash))

    return indicators


def run_cti_enrichment(state: SOCInvestigationState) -> dict:
    """CTI Enrichment agent node.

    Runs in parallel with log_investigator and attck_mapper -- must return
    only the keys it touches (see agents/log_investigator.py for why). For
    the same reason it keys off alert_raw / alert_category only (both
    written before the parallel fan-out) and never log_output / attck_output,
    which are sibling branches in this same superstep and are not
    guaranteed to be populated yet.
    """
    alert_raw = state.get("alert_raw") or {}
    category  = state.get("alert_category")

    prefetched_indicators = _prefetch_ioc_indicators(alert_raw)

    keywords = [k for k in [alert_raw.get("process"), alert_raw.get("user")] if k]
    cti_context = retrieveCTIContext(category, keywords)

    alert_context = (
        f"Alert ID: {alert_raw.get('alert_id', 'N/A')}\n"
        f"Category: {category or 'N/A'}\n"
        f"Source: {alert_raw.get('source', 'N/A')}\n"
        f"User: {alert_raw.get('user', 'N/A')}\n"
        f"Hostname: {alert_raw.get('hostname', 'N/A')}\n"
        f"Raw Log: {alert_raw.get('raw_log', 'N/A')}\n"
        f"Timestamp: {alert_raw.get('timestamp', 'N/A')}"
    )
    enriched_context = (
        f"{alert_context}\n\n"
        f"=== IOC LOOKUPS (MCP read-only tools) ===\n{prefetched_indicators}\n\n"
        f"=== RAG-RETRIEVED CTI CONTEXT ===\n{cti_context}"
    )

    llm = get_provider("cti_enrichment")
    response = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Enrich the threat intelligence for this security alert:\n\n{enriched_context}")
    ])

    parsed = _parse_json_response(response.content)
    output = CTIEnrichmentOutput(
        indicators=parsed.get("indicators") or prefetched_indicators,
        cti_context=cti_context,
        cti_confidence=float(parsed.get("cti_confidence", 0.0)),
        threat_summary=parsed.get("threat_summary", ""),
    )

    return {
        "cti_output": output.model_dump(),
        "agents_completed": ["cti_enrichment"],
    }


def _parse_json_response(content: str) -> dict:
    """Extract and parse the first JSON object from an LLM response string."""
    import json
    try:
        return json.loads(content.strip())
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return {}
