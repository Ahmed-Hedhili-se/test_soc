"""
tests/test_pipeline.py

Test suite for the SOC Assistant multi-agent pipeline.

Tests:
  1. Graph compiles without errors
  2. Routing: impossible_travel skips log_investigator
  3. Routing: malware triggers log_investigator
  4. HITL safety gate: write tools reject missing approved_by
  5. Full end-to-end pipeline for each of the sample alerts
  6. Override rate calculation
"""
from __future__ import annotations

import json
import os
import sys
import pytest
from pathlib import Path
from datetime import datetime, timezone

# Enable mock embeddings for testing to avoid heavy downloads and network dependencies
os.environ["SOC_ASSISTANT_MOCK_EMBEDDINGS"] = "1"

# Ensure soc-assistant is on the path
SYS_PATH = Path(__file__).parent.parent
if str(SYS_PATH) not in sys.path:
    sys.path.insert(0, str(SYS_PATH))

os.chdir(SYS_PATH)  # so config/thresholds.yaml is readable


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def soc_graph():
    from orchestrator.graph import build_soc_graph
    return build_soc_graph()


@pytest.fixture(scope="session")
def sample_alerts():
    path = Path("data/alerts/sample_alerts.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _make_state(alert: dict) -> dict:
    return {
        "alert_id":           alert["alert_id"],
        "alert_raw":          alert,
        "alert_category":     alert["category"],
        "alert_timestamp":    alert["timestamp"],
        "agents_activated":   [],
        "agents_completed":   [],
        "agents_failed":      [],
        "missing_evidence":   [],
        "audit_log":          [],
        "tool_calls_count":   {},
        "confidence_score":   0.0,
        "escalation_flag":    False,
        "pipeline_start_time": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Test 1: Graph compiles
# ---------------------------------------------------------------------------

def test_graph_compiles(soc_graph):
    """The LangGraph StateGraph must compile without raising."""
    assert soc_graph is not None


# ---------------------------------------------------------------------------
# Test 2 & 3: Routing
# ---------------------------------------------------------------------------

def test_routing_impossible_travel():
    """
    For impossible_travel alerts, the router must skip log_investigator
    and dispatch cti_enrichment and attck_mapper.
    """
    from orchestrator.graph import route_after_triage

    state = {
        "alert_id": "test-routing-1",
        "alert_raw": {"category": "impossible_travel"},
        "alert_category": "impossible_travel",
        "triage_output": {"severity": 7.5, "category": "impossible_travel",
                          "fp_probability": 0.2, "authorized_activity": False},
        "confidence_score": 0.0,
        "agents_completed": [],
    }
    node_names = route_after_triage(state)
    assert "log_investigator" not in node_names, "log_investigator must be skipped for impossible_travel"
    assert "cti_enrichment" in node_names
    assert "attck_mapper"   in node_names


def test_routing_malware_includes_log_investigator():
    """
    For malware alerts, log_investigator must be in the routing targets.
    """
    from orchestrator.graph import route_after_triage

    state = {
        "alert_id": "test-routing-2",
        "alert_raw": {"category": "malware"},
        "alert_category": "malware",
        "triage_output": {"severity": 9.0, "category": "malware",
                          "fp_probability": 0.05, "authorized_activity": False},
        "confidence_score": 0.0,
        "agents_completed": [],
    }
    node_names = route_after_triage(state)
    assert "log_investigator" in node_names
    assert "cti_enrichment"   in node_names
    assert "attck_mapper"     in node_names


# ---------------------------------------------------------------------------
# Test 4: HITL safety gate
# ---------------------------------------------------------------------------

def test_write_tool_rejects_missing_approval():
    """isolateHost must raise HTTP 403 if approved_by is missing."""
    from fastapi import HTTPException
    from mcp_tools.write.api import isolateHost, WriteActionInput

    with pytest.raises(HTTPException) as exc_info:
        isolateHost(WriteActionInput(
            approved_by="",
            target="WS-SALES-01",
            justification="test",
        ))
    assert exc_info.value.status_code == 403


def test_write_tool_succeeds_with_approval():
    """isolateHost must succeed when approved_by is set."""
    from mcp_tools.write.api import isolateHost, WriteActionInput

    result = isolateHost(WriteActionInput(
        approved_by="analyst-jane",
        target="WS-SALES-01",
        justification="Malware confirmed",
        alert_id="ALT-2026-002",
    ))
    assert result["status"] == "simulated"
    assert result["approved_by"] == "analyst-jane"


# ---------------------------------------------------------------------------
# Test 5: Full end-to-end pipeline (all sample alerts)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alert_index", [0, 1, 2, 3])
def test_full_pipeline(soc_graph, sample_alerts, alert_index):
    """
    Run each sample alert through the full pipeline and assert:
      - All required output keys are populated
      - Synthesis output contains a valid verdict
      - Report output is a non-empty dict
      - Confidence score is between 0 and 1
    """
    alert = sample_alerts[alert_index]
    initial_state = _make_state(alert)
    config = {"configurable": {"thread_id": f"test-{alert['alert_id']}"}}

    final_state = soc_graph.invoke(initial_state, config=config)

    # Triage output must exist
    assert final_state.get("triage_output") is not None, f"Missing triage_output for {alert['alert_id']}"
    triage = final_state["triage_output"]
    assert 0 <= triage["severity"] <= 10
    assert 0 <= triage["fp_probability"] <= 1

    # Synthesis must exist and have a valid verdict
    assert final_state.get("synthesis_output") is not None
    synthesis = final_state["synthesis_output"]
    assert synthesis["verdict"] in ("actionable", "needs_investigation", "inconclusive", "false_positive")
    assert 0 <= synthesis["confidence"] <= 1

    # Confidence score must be set
    assert 0.0 <= final_state.get("confidence_score", -1) <= 1.0

    # Report must exist
    assert final_state.get("report_output") is not None
    report = final_state["report_output"]
    assert "executive_summary" in report
    assert "remediation_proposals" in report

    # Agents completed must not be empty
    completed = final_state.get("agents_completed", [])
    assert "triage" in completed
    assert "reasoning_synthesis" in completed
    assert "report_generator" in completed

    print(f"\n[PASS] {alert['alert_id']} | verdict={synthesis['verdict']} | confidence={synthesis['confidence']:.1%}")


# ---------------------------------------------------------------------------
# Test 6: Override rate calculation
# ---------------------------------------------------------------------------

def test_override_rate_by_role():
    """calculate_override_rate_by_role must return per-agent rates."""
    from eval.override_rate import calculate_override_rate_by_role

    decisions = [
        {"action": "modify",  "corrected_fields": ["triage_output.severity"]},
        {"action": "approve", "corrected_fields": []},
        {"action": "reject",  "corrected_fields": ["attck_output.technique_ids", "triage_output.fp_probability"]},
        {"action": "modify",  "corrected_fields": ["synthesis_output.verdict"]},
    ]
    rates = calculate_override_rate_by_role(decisions)

    # triage was corrected in 2 of 3 decisions that touched it
    assert "triage" in rates
    assert rates["triage"] > 0.5

    # attck_mapper was corrected in 1 of 1 decision that touched it
    assert "attck_mapper" in rates
    assert rates["attck_mapper"] == 1.0

    # reasoning_synthesis was corrected in 1 of 1
    assert "reasoning_synthesis" in rates
    assert rates["reasoning_synthesis"] == 1.0
