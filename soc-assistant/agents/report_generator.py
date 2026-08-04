"""
agents/report_generator.py

Report Generator agent -- final node in the pipeline.
Calls the configured LLM (see config/provider.py) to generate a structured
incident report with remediation proposals based on the complete
investigation findings.

Returns a partial update, same reasoning as agents/synthesis.py.
"""
from __future__ import annotations

import json
import re

from langchain_core.messages import SystemMessage, HumanMessage

from config.provider import get_provider
from state.investigation import SOCInvestigationState


_SYSTEM_PROMPT = """You are a SOC Report Writer. Based on a complete security investigation, generate a structured incident report with concrete remediation proposals.

Each remediation proposal must specify:
- action: A short action name (e.g. "isolateHost", "blockIP", "resetCredentials", "reviewFirewallRules")
- description: A 1-sentence description of what should be done and why.
- requires_approval: true if this action changes the environment (ALWAYS true -- no agent may modify the real environment without analyst approval).

You MUST respond with ONLY a valid JSON object in this exact format, no explanations:
{
  "executive_summary": "<2-3 sentence high-level summary for management>",
  "evidence_chain": {
    "triage": "<key triage findings>",
    "logs": "<key log findings>",
    "cti": "<key threat intel findings>",
    "attck": "<key ATT&CK findings>"
  },
  "attck_technique_cards": [{"id": "<T-ID>", "name": "<name>", "description": "<1-line>"}],
  "remediation_proposals": [
    {
      "action": "<action_name>",
      "description": "<what to do and why>",
      "requires_approval": true
    }
  ]
}"""


def run_report_generator(state: SOCInvestigationState) -> dict:
    """Report Generator agent node -- calls the configured LLM to draft the report.

    Final node in the pipeline. Returns a partial update -- only report_output
    and agents_completed, same pattern as all other nodes.
    """
    alert     = state.get("alert_raw", {})
    triage    = state.get("triage_output", {}) or {}
    log_out   = state.get("log_output", {}) or {}
    cti_out   = state.get("cti_output", {}) or {}
    attck_out = state.get("attck_output", {}) or {}
    synthesis = state.get("synthesis_output", {}) or {}

    investigation_summary = (
        f"=== ALERT ===\n"
        f"ID: {alert.get('alert_id')} | Category: {alert.get('category')} | Source: {alert.get('source')}\n"
        f"Raw Log: {alert.get('raw_log', '')}\n\n"
        f"=== VERDICT ===\n"
        f"Verdict: {synthesis.get('verdict')} | Confidence: {synthesis.get('confidence')} | "
        f"Remediation Required: {synthesis.get('remediation_required')}\n"
        f"Narrative: {synthesis.get('narrative')}\n\n"
        f"=== TRIAGE ===\n"
        f"Severity: {triage.get('severity')} | FP Probability: {triage.get('fp_probability')}\n\n"
        f"=== LOG FINDINGS ===\n"
        f"Anomalies: {log_out.get('anomalies', [])} | Timeline: {log_out.get('timeline', [])}\n\n"
        f"=== CTI ===\n"
        f"Indicators: {cti_out.get('indicators', [])} | Summary: {cti_out.get('threat_summary', 'N/A')}\n\n"
        f"=== ATT&CK ===\n"
        f"Techniques: {attck_out.get('technique_ids', [])} | Tactics: {attck_out.get('observed_tactics', [])} | "
        f"Predicted Next: {attck_out.get('predicted_next', [])}"
    )

    llm = get_provider("report_generator")
    response = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Generate the incident report for this completed investigation:\n\n{investigation_summary}")
    ])

    parsed = _parse_json_response(response.content)

    # Ensure every remediation proposal explicitly requires_approval=True (HITL invariant)
    proposals = parsed.get("remediation_proposals", [])
    for p in proposals:
        p["requires_approval"] = True

    report = {
        "executive_summary": parsed.get("executive_summary", ""),
        "evidence_chain": parsed.get("evidence_chain", {}),
        "attck_technique_cards": parsed.get("attck_technique_cards", []),
        "confidence": state.get("confidence_score", 0.0),
        "uncertainty_flags": synthesis.get("missing_evidence", []),
        "remediation_proposals": proposals if proposals else [
            {"action": "analystReview", "description": "Manual analyst review required.", "requires_approval": True}
        ],
    }

    return {
        "report_output": report,
        "agents_completed": ["report_generator"],
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
