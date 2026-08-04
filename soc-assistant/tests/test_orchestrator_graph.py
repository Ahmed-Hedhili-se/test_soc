"""
Regression tests for orchestrator/graph.py.

Run from the soc-assistant/ directory:
    pytest tests/test_orchestrator_graph.py -v
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# No live Ollama/vLLM server in CI -- get_provider() returns a
# deterministic mock completion per role instead (see config/provider.py).
os.environ["SOC_ASSISTANT_MOCK_EMBEDDINGS"] = "1"
os.environ["SOC_ASSISTANT_MOCK_LLM"] = "1"

import pytest
from orchestrator.graph import build_soc_graph, route_after_triage


def make_state(category="credential_access", severity=5.0, confidence=0.5):
    return {
        "alert_id": f"test-{category}",
        # triage (now a real LLM-calling agent, see agents/triage.py) reads
        # category from alert_raw, not alert_category -- mock-LLM mode
        # falls back to alert_raw.get("category") when it omits the field.
        "alert_raw": {"x": 1, "category": category},
        "alert_category": category,
        "alert_timestamp": "2026-01-01",
        "triage_output": {"severity": severity, "category": category},
        "confidence_score": confidence,
        "agents_activated": [],
        "agents_completed": [],
        "agents_failed": [],
        "tool_calls_count": {},
        "synthesis_output": None,
        "report_output": None,
        "escalation_flag": False,
        "hitl_decision": None,
        "analyst_note": None,
        "approved_by": None,
        "audit_log": [],
        "pipeline_start_time": "2026-01-01",
        "pipeline_end_time": None,
        "log_output": None,
        "cti_output": None,
        "attck_output": None,
        "missing_evidence": [],
    }


def test_graph_compiles():
    app = build_soc_graph()
    assert app is not None


def test_route_after_triage_default_path_activates_all_three():
    state = make_state(category="credential_access")
    targets = route_after_triage(state)
    assert set(targets) == {"log_investigator", "cti_enrichment", "attck_mapper"}


def test_route_after_triage_impossible_travel_skips_log_investigator():
    state = make_state(category="impossible_travel")
    targets = route_after_triage(state)
    assert set(targets) == {"cti_enrichment", "attck_mapper"}
    assert "log_investigator" not in targets


@pytest.mark.parametrize(
    "category,expected_agents",
    [
        ("credential_access", {"triage", "log_investigator", "cti_enrichment", "attck_mapper", "reasoning_synthesis", "report_generator"}),
        ("impossible_travel", {"triage", "cti_enrichment", "attck_mapper", "reasoning_synthesis", "report_generator"}),
    ],
)
def test_full_graph_invoke_reaches_expected_agents_exactly_once_each(category, expected_agents):
    """
    Regression test for the bug where agent nodes returning the FULL
    mutated state (instead of a partial update dict) caused
    `agents_completed` to accumulate duplicate entries via the
    Annotated[list, operator.add] reducer -- every node's contribution
    got re-added on top of the already-accumulated list by every
    downstream node that also (incorrectly) returned the full state.

    This test would fail loudly (via the `Counter` assertion) if any
    agent module regresses to that pattern.
    """
    from collections import Counter

    app = build_soc_graph()
    result = app.invoke(
        make_state(category=category),
        config={"configurable": {"thread_id": f"test-{category}"}},
    )

    completed = result.get("agents_completed", [])
    counts = Counter(completed)

    assert set(completed) == expected_agents, (
        f"Expected exactly {expected_agents}, got {set(completed)}"
    )
    duplicated = {name: n for name, n in counts.items() if n != 1}
    assert not duplicated, (
        f"Each agent should complete exactly once per run; found duplicates: {duplicated}. "
        f"This usually means an agent is returning the full state dict instead of a "
        f"partial update (see agents/synthesis.py docstring)."
    )
    assert result.get("report_output") is not None


def test_invalid_update_error_does_not_occur_on_parallel_fanout():
    """
    Direct regression test for the original InvalidUpdateError
    ("Can receive only one value per step") that occurred when parallel
    branches (log_investigator / cti_enrichment / attck_mapper) each
    returned the full state, causing every unrelated field (e.g. alert_id)
    to be "written" by more than one branch in the same superstep.
    """
    app = build_soc_graph()
    try:
        app.invoke(
            make_state(category="credential_access"),
            config={"configurable": {"thread_id": "test-invalid-update"}},
        )
    except Exception as e:
        if "InvalidUpdateError" in type(e).__name__ or "Can receive only one value per step" in str(e):
            pytest.fail(f"Parallel fan-out is broken again: {e}")
        raise
