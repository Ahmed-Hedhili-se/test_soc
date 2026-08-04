"""
agents/synthesis.py

Reasoning & Synthesis agent -- runs after all parallel branches converge.
Calls the configured LLM (see config/provider.py) to reconcile all agent
outputs into a final verdict and escalation decision.

Like every other node in this graph, it must return a PARTIAL update (only
the keys it touches). Returning the full state here was the actual root
cause of a bug where every node's contribution to `agents_completed`
appeared duplicated: this node used to read the already-accumulated
`agents_completed` list, append one entry, and return the WHOLE list as
part of the full state -- which LangGraph's `operator.add` reducer then
added ON TOP OF the existing channel value a second time, compounding
with every downstream node. See tests/test_orchestrator_graph.py for the
regression test.
"""
from __future__ import annotations

import json
import re

import yaml
from langchain_core.messages import SystemMessage, HumanMessage

from config.provider import get_provider
from state.investigation import SOCInvestigationState
from models.synthesis import SynthesisOutput


_SYSTEM_PROMPT = """You are the senior SOC analyst responsible for final verdict synthesis. You receive structured outputs from four specialized agents (Triage, Log Investigator, CTI Enrichment, ATT&CK Mapper) and must synthesize them into a final, evidence-based verdict.

Your verdict must be one of:
- "actionable": Confirmed threat requiring immediate remediation.
- "needs_investigation": Suspicious but requires more evidence before acting.
- "false_positive": Alert is benign; no action required.

You MUST respond with ONLY a valid JSON object in this exact format, no explanations:
{
  "verdict": "<actionable|needs_investigation|false_positive>",
  "confidence": <float 0.0-1.0>,
  "narrative": "<2-3 sentence evidence-based explanation of verdict>",
  "remediation_required": <true|false>,
  "escalation_reason": "<reason or null>",
  "missing_evidence": ["<gap in evidence if any>"]
}"""


def run_synthesis(state: SOCInvestigationState) -> dict:
    """Synthesis agent node -- calls the configured LLM to produce the final verdict.

    Runs after all three parallel branches converge. Returns a PARTIAL update
    (only the keys it touches) to avoid LangGraph reducer duplication bugs.
    """
    try:
        with open("config/thresholds.yaml", "r") as f:
            thresholds = yaml.safe_load(f)["escalation_policy"]
    except Exception:
        thresholds = {"approval_required_threshold": 0.80, "uncertain_threshold": 0.65}

    alert     = state.get("alert_raw", {})
    triage    = state.get("triage_output", {}) or {}
    log_out   = state.get("log_output", {}) or {}
    cti_out   = state.get("cti_output", {}) or {}
    attck_out = state.get("attck_output", {}) or {}

    evidence_summary = (
        f"=== ALERT ===\n"
        f"ID: {alert.get('alert_id')} | Category: {alert.get('category')} | Raw Log: {alert.get('raw_log', '')}\n\n"
        f"=== TRIAGE ===\n"
        f"Severity: {triage.get('severity')} | FP Probability: {triage.get('fp_probability')} | "
        f"Category: {triage.get('category')} | Authorized: {triage.get('authorized_activity')}\n\n"
        f"=== LOG INVESTIGATION ===\n"
        f"Anomalies: {log_out.get('anomalies', [])} | Timeline: {log_out.get('timeline', [])}\n\n"
        f"=== CTI ENRICHMENT ===\n"
        f"Indicators: {cti_out.get('indicators', [])} | CTI Confidence: {cti_out.get('cti_confidence', 0)} | "
        f"Threat Summary: {cti_out.get('threat_summary', 'N/A')}\n\n"
        f"=== MITRE ATT&CK ===\n"
        f"Techniques: {attck_out.get('technique_ids', [])} | Tactics: {attck_out.get('observed_tactics', [])} | "
        f"Predicted Next: {attck_out.get('predicted_next', [])}"
    )

    llm = get_provider("reasoning_synthesis")
    response = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Synthesize a final verdict from this aggregated evidence:\n\n{evidence_summary}")
    ])

    parsed = _parse_json_response(response.content)
    verdict               = parsed.get("verdict") or "needs_investigation"
    confidence             = float(parsed.get("confidence", 0.5))
    remediation_required   = bool(parsed.get("remediation_required", False))
    escalation_reason      = parsed.get("escalation_reason")

    if remediation_required and confidence >= thresholds["approval_required_threshold"]:
        escalation_reason = escalation_reason or "High-confidence actionable verdict requires HITL approval"
    elif not escalation_reason and confidence < thresholds["uncertain_threshold"]:
        escalation_reason = "Auto-escalate: confidence below uncertain threshold"

    output = SynthesisOutput(
        verdict=verdict,
        confidence=confidence,
        narrative=parsed.get("narrative", ""),
        remediation_required=remediation_required,
        escalation_reason=escalation_reason,
        missing_evidence=parsed.get("missing_evidence") or state.get("missing_evidence", []),
    )

    return {
        "synthesis_output": output.model_dump(),
        "confidence_score": confidence,
        "escalation_flag": escalation_reason is not None,
        "agents_completed": ["reasoning_synthesis"],
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
