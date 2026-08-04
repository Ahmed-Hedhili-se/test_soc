"""
agents/attck_mapper.py

ATT&CK Mapper agent -- runs in parallel with log_investigator and cti_enrichment.

Pre-fetches deterministic candidate techniques via the RAG knowledge base
(category lookup + raw-log semantic search), then calls the configured
LLM (see config/provider.py) to reason over them. If the LLM's parsed
response omits a field (e.g. SOC_ASSISTANT_MOCK_LLM=1, or a malformed
completion), the RAG-derived value is used instead -- this agent always
returns something useful even with no live model behind it.
"""
from __future__ import annotations

import json
import re

from langchain_core.messages import SystemMessage, HumanMessage

from config.provider import get_provider
from state.investigation import SOCInvestigationState
from schemas.agent_io import ATTCKMapperOutput
from mcp_tools.rag.api import (
    techniquesForCategory,
    getTechniqueDetail,
    buildTacticChain,
    killChainPosition,
    predictNextTactics,
)
from rag.store_attck import get_attck_store


_SYSTEM_PROMPT = """You are an expert MITRE ATT&CK Framework analyst. Your job is to map security alert behaviors to specific ATT&CK techniques and tactics.

Given an alert, identify:
1. technique_ids: List of relevant MITRE ATT&CK technique IDs (e.g. ["T1078", "T1021.001"]).
2. kill_chain_position: The furthest kill chain stage reached (1=Reconnaissance ... 14=Impact).
3. observed_tactics: List of tactic names observed (e.g. ["initial-access", "execution"]).
4. predicted_next: List of likely next-stage tactics the attacker may attempt.

You MUST respond with ONLY a valid JSON object in this exact format, no explanations:
{
  "technique_ids": ["<technique_id>"],
  "kill_chain_position": <int 1-14>,
  "observed_tactics": ["<tactic>"],
  "predicted_next": ["<tactic>"]
}"""


def run_attck_mapper(state: SOCInvestigationState) -> dict:
    """ATT&CK Mapper agent node.

    Runs in parallel with log_investigator and cti_enrichment -- must
    return only the keys it touches (see agents/log_investigator.py for
    why). Keys off alert_category / triage_output / alert_raw only, all
    written before the parallel fan-out; log_output and cti_output are
    sibling branches in this same superstep and are not guaranteed to be
    populated yet.
    """
    alert_raw = state.get("alert_raw") or {}
    category  = state.get("alert_category") or (state.get("triage_output") or {}).get("category")

    candidates    = techniquesForCategory(category)
    candidate_ids = [t["id"] for t in candidates]

    # Supplementary semantic search over the raw log text, in case the
    # category-based candidate list misses something the free-text log
    # would surface (falls back to an empty result set if the store isn't
    # indexed/available -- see rag/store_attck.py).
    raw_log = alert_raw.get("raw_log", "") or ""
    try:
        rag_docs = get_attck_store().similarity_search(raw_log, k=3) if raw_log else []
        rag_context = "\n".join(f"- {doc.page_content}" for doc in rag_docs)
    except Exception:
        rag_context = ""

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
        f"=== CANDIDATE TECHNIQUES FOR CATEGORY '{category}' (RAG) ===\n"
        f"{candidates}\n\n"
        f"=== SEMANTIC RAG SEARCH OVER RAW LOG ===\n{rag_context}"
    )

    llm = get_provider("attck_mapper")
    response = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Map the MITRE ATT&CK techniques for this security alert:\n\n{enriched_context}")
    ])

    parsed = _parse_json_response(response.content)

    technique_ids     = parsed.get("technique_ids") or candidate_ids
    observed_tactics   = parsed.get("observed_tactics") or buildTacticChain(technique_ids)
    kill_chain_pos     = int(parsed.get("kill_chain_position") or killChainPosition(observed_tactics))
    predicted_next      = parsed.get("predicted_next") or predictNextTactics(observed_tactics)
    technique_details   = [getTechniqueDetail(tid) for tid in technique_ids]

    output = ATTCKMapperOutput(
        technique_ids=technique_ids,
        kill_chain_position=kill_chain_pos,
        observed_tactics=observed_tactics,
        predicted_next=predicted_next,
        technique_details=technique_details,
    )

    return {
        "attck_output": output.model_dump(),
        "agents_completed": ["attck_mapper"],
    }


def _parse_json_response(content: str) -> dict:
    """Extract and parse the first JSON object from an LLM response string."""
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
