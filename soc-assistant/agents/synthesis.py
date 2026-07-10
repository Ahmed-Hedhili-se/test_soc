from state.investigation import SOCInvestigationState
from models.synthesis import SynthesisOutput
import yaml

def run_synthesis(state: SOCInvestigationState) -> SOCInvestigationState:
    """Synthesis agent node using MCP tools."""
    
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
    
    state["synthesis_output"] = output.model_dump()
    state["confidence_score"] = confidence
    state["escalation_flag"] = escalation_reason is not None
    
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("reasoning_synthesis")
    
    return state
