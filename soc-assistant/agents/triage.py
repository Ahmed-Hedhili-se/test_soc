"""
agents/triage.py

Triage agent -- first node in the pipeline. Runs alone before the parallel fan-out.
Calls the configured LLM (see config/provider.py) and returns a structured TriageOutput.
"""
from __future__ import annotations

import json
import re

from langchain_core.messages import SystemMessage, HumanMessage

from config.provider import get_provider
from state.investigation import SOCInvestigationState
from schemas.agent_io import TriageOutput


_SYSTEM_PROMPT = """You are an expert SOC Triage Analyst. Your job is to analyze security alerts and determine:
1. Severity (0.0-10.0): How critical is this alert?
2. FP Probability (0.0-1.0): How likely is this a false positive?
3. Category: The alert category (use the one provided if accurate, otherwise correct it).
4. Authorized Activity (true/false): Is this likely authorized/expected behavior?

You MUST respond with ONLY a valid JSON object in this exact format, no explanations:
{
  "severity": <float 0.0-10.0>,
  "fp_probability": <float 0.0-1.0>,
  "category": "<string>",
  "authorized_activity": <true|false>
}"""


def run_triage_agent(state: SOCInvestigationState) -> dict:
    """Triage agent node -- calls the configured LLM to assess the alert.

    Returns a PARTIAL state update (only the keys this node touches). Triage runs
    alone before the parallel fan-out so it writes to triage_output exclusively.
    """
    alert = state.get("alert_raw", {})
    alert_context = (
        f"Alert ID: {alert.get('alert_id', 'N/A')}\n"
        f"Category: {alert.get('category', 'N/A')}\n"
        f"Severity (raw): {alert.get('severity', 'N/A')}\n"
        f"Source: {alert.get('source', 'N/A')}\n"
        f"User: {alert.get('user', 'N/A')}\n"
        f"Hostname: {alert.get('hostname', 'N/A')}\n"
        f"Raw Log: {alert.get('raw_log', 'N/A')}\n"
        f"Timestamp: {alert.get('timestamp', 'N/A')}"
    )

    llm = get_provider("triage")
    response = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Analyze this security alert:\n\n{alert_context}")
    ])

    parsed = _parse_json_response(response.content)
    output = TriageOutput(
        severity=float(parsed.get("severity", 5.0)),
        fp_probability=float(parsed.get("fp_probability", 0.5)),
        category=str(parsed.get("category") or alert.get("category", "unknown")),
        authorized_activity=bool(parsed.get("authorized_activity", False)),
    )

    return {
        "triage_output": output.model_dump(),
        "agents_completed": ["triage"],
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
