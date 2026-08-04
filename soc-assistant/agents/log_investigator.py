"""
agents/log_investigator.py

Log Investigator agent -- runs in parallel with cti_enrichment and attck_mapper.
Calls the configured LLM (see config/provider.py) to correlate log events and
identify anomalies.

Runs in parallel with cti_enrichment and attck_mapper (same LangGraph
superstep). MUST return only the keys it touches -- returning the full
state object here causes LangGraph's InvalidUpdateError the moment more
than one parallel branch actually executes, because unrelated fields
like alert_id would be "written" by every branch simultaneously.
"""
from __future__ import annotations

import json
import re

from langchain_core.messages import SystemMessage, HumanMessage

from config.provider import get_provider
from state.investigation import SOCInvestigationState
from schemas.agent_io import LogInvestigatorOutput
from mcp_tools.read_only.api import querySIEMLogs, getProcessTree


_SYSTEM_PROMPT = """You are an expert SOC Log Investigator. Your job is to analyze security alert logs and identify:
1. Events: Key log events related to this alert.
2. Entities: Extracted entities (IPs, usernames, processes).
3. Timeline: Ordered sequence of key events.
4. Anomalies: Suspicious behaviors found (e.g. unusual parent-child process relationships, lateral movement indicators).

You MUST respond with ONLY a valid JSON object in this exact format, no explanations:
{
  "events": [{"timestamp": "<string>", "description": "<string>"}],
  "entities": {"ips": ["<ip>"], "users": ["<user>"], "processes": ["<process>"]},
  "timeline": ["<event string>"],
  "anomalies": ["<anomaly description>"]
}"""


def run_log_investigator(state: SOCInvestigationState) -> dict:
    """Log investigator agent node -- calls the configured LLM to analyze logs.

    Keys off alert_raw only (available before the parallel fan-out); never
    reads cti_output / attck_output, which are sibling branches in this
    same superstep and are not guaranteed to be populated yet.
    """
    alert = state.get("alert_raw", {})
    alert_context = (
        f"Alert ID: {alert.get('alert_id', 'N/A')}\n"
        f"Category: {alert.get('category', 'N/A')}\n"
        f"Source: {alert.get('source', 'N/A')}\n"
        f"Hostname: {alert.get('hostname', 'N/A')}\n"
        f"User: {alert.get('user', 'N/A')}\n"
        f"Raw Log: {alert.get('raw_log', 'N/A')}\n"
        f"Timestamp: {alert.get('timestamp', 'N/A')}"
    )

    # --- Pre-fetch context using MCP tools ---
    user = alert.get("user")
    host = alert.get("hostname")

    source_ip = alert.get("source_ip")
    if not source_ip:
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", alert.get("raw_log", ""))
        source_ip = ip_match.group() if ip_match else None

    siem_logs = querySIEMLogs(query_terms=["*"], user=user, host=host, source_ip=source_ip)
    process_tree = getProcessTree(host=host)

    enriched_context = (
        f"{alert_context}\n\n"
        f"=== ENRICHED DATA FROM MCP TOOLS ===\n"
        f"SIEM Logs (Related to user/host/ip):\n{json.dumps(siem_logs, indent=2)}\n\n"
        f"Process Tree for host {host}:\n{json.dumps(process_tree, indent=2)}\n"
    )

    llm = get_provider("log_investigator")
    response = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Investigate the logs for this security alert:\n\n{enriched_context}")
    ])

    parsed = _parse_json_response(response.content)
    output = LogInvestigatorOutput(
        events=parsed.get("events", []),
        entities=parsed.get("entities") or {"ips": [], "users": [], "processes": []},
        timeline=parsed.get("timeline", []),
        anomalies=parsed.get("anomalies", []),
    )

    return {
        "log_output": output.model_dump(),
        "agents_completed": ["log_investigator"],
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
