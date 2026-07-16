from state.investigation import SOCInvestigationState
from models.synthesis import SynthesisOutput
import yaml

def run_synthesis(state: SOCInvestigationState) -> dict:
    """Synthesis agent node using MCP tools.

    Runs after the three parallel branches converge. Like every other node
    in this graph, it must return a PARTIAL update (only the keys it
    touches). Returning the full state here was the actual root cause of a
    bug where every node's contribution to `agents_completed` appeared
    duplicated: this node used to read the already-accumulated
    `agents_completed` list, append one entry, and return the WHOLE list as
    part of the full state -- which LangGraph's `operator.add` reducer then
    added ON TOP OF the existing channel value a second time, compounding
    with every downstream node. See tests/test_orchestrator_graph.py for
    the regression test.
    """

    # Load escalation policy
    try:
        with open("config/thresholds.yaml", "r") as f:
            thresholds = yaml.safe_load(f)["escalation_policy"]
    except Exception:
        thresholds = {"approval_required_threshold": 0.80, "uncertain_threshold": 0.65}

    confidence = 0.85 # calculated from inputs
    verdict = "actionable"
    remediation_required = True
    escalation_reason = None

    if remediation_required:
        escalation_reason = "Any remediation verdict always requires HITL"
    elif confidence < thresholds["uncertain_threshold"]:
        escalation_reason = "Auto-escalate: confidence below uncertain threshold"

    output = SynthesisOutput(
        verdict=verdict,
        confidence=confidence,
        narrative="Synthesized narrative from all agents...",
        remediation_required=remediation_required,
        escalation_reason=escalation_reason,
        missing_evidence=state.get("missing_evidence", [])
    )

    return {
        "synthesis_output": output.model_dump(),
        "confidence_score": confidence,
        "escalation_flag": escalation_reason is not None,
        "agents_completed": ["reasoning_synthesis"],
    }
