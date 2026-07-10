def calculate_override_rate(analyst_modifications: int, total_hitl_decisions: int) -> float:
    """
    override_rate = analyst_modifications / total_hitl_decisions
    Should be computed per-agent-role.
    """
    if total_hitl_decisions == 0: return 0.0
    return analyst_modifications / total_hitl_decisions
