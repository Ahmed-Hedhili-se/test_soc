from state.investigation import SOCInvestigationState
from schemas.alert import NormalizedAlert
from schemas.agent_io import TriageOutput
from typing import Dict, Any

def run_triage_agent(state: SOCInvestigationState) -> dict:
    """Triage agent node using MCP tools.

    Returns a PARTIAL state update (only the keys this node touches), not
    the full state object. Triage runs alone before the parallel fan-out,
    so this specific node would not strictly need to follow this rule today
    -- but every downstream agent does (see agents/log_investigator.py for
    why), so triage follows the same convention for consistency.
    """
    # Stub: checkMaintenanceWindow should be checked before final severity is computed
    # Stub: Tool budget check

    # Example typed output mapping
    output = TriageOutput(
        severity=7.5,
        fp_probability=0.2,
        category=state.get("alert_category", "other"),
        authorized_activity=False
    )

    return {
        "triage_output": output.model_dump(),
        "agents_completed": ["triage"],
    }
