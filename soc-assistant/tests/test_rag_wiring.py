"""
tests/test_rag_wiring.py

Regression tests for the RAG knowledge base <-> agent connections
(mcp_tools/rag/api.py, agents/cti_enrichment.py, agents/attck_mapper.py,
rag/store_ioc.py).

Run from the soc-assistant/ directory:
    pytest tests/test_rag_wiring.py -v
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["SOC_ASSISTANT_MOCK_EMBEDDINGS"] = "1"
os.environ["SOC_ASSISTANT_MOCK_LLM"] = "1"

SYS_PATH = Path(__file__).parent.parent
if str(SYS_PATH) not in sys.path:
    sys.path.insert(0, str(SYS_PATH))
os.chdir(SYS_PATH)

import pytest


# ---------------------------------------------------------------------------
# mcp_tools/rag/api.py helpers
# ---------------------------------------------------------------------------

def test_techniques_for_category_known():
    from mcp_tools.rag.api import techniquesForCategory
    techniques = techniquesForCategory("malware")
    ids = {t["id"] for t in techniques}
    assert "T1566.001" in ids
    assert "T1059.001" in ids


def test_techniques_for_category_unknown_returns_empty():
    from mcp_tools.rag.api import techniquesForCategory
    assert techniquesForCategory("not_a_real_category") == []
    assert techniquesForCategory(None) == []


def test_kill_chain_position_orders_by_tactic():
    from mcp_tools.rag.api import killChainPosition
    # defense-evasion comes after initial-access in _TACTIC_ORDER
    assert killChainPosition(["initial-access"]) < killChainPosition(["initial-access", "defense-evasion"])
    assert killChainPosition([]) == 0


def test_predict_next_tactics_continues_the_chain():
    from mcp_tools.rag.api import buildTacticChain, predictNextTactics, techniquesForCategory

    techniques = techniquesForCategory("malware")
    observed = buildTacticChain([t["id"] for t in techniques])
    predicted = predictNextTactics(observed, lookahead=2)

    assert len(predicted) <= 2
    assert not (set(predicted) & set(observed)), "predicted tactics must not repeat observed ones"


def test_predict_next_tactics_empty_when_nothing_observed():
    from mcp_tools.rag.api import predictNextTactics
    assert predictNextTactics([]) == []


def test_get_technique_detail_falls_back_to_builtin_table():
    from mcp_tools.rag.api import getTechniqueDetail
    detail = getTechniqueDetail("T1078")
    assert detail["id"] == "T1078"
    assert "Valid Accounts" in detail["content"] or detail.get("name") == "Valid Accounts"


# ---------------------------------------------------------------------------
# rag/store_ioc.py exclusivity helper
# ---------------------------------------------------------------------------

def test_ioc_exclusivity_roundtrip(tmp_path, monkeypatch):
    import rag.store_ioc as store_ioc

    # Point the module at a throwaway DB so this test can't pollute the
    # real rag/db/iocs.db or interfere with other tests.
    monkeypatch.setattr(store_ioc, "_DB_PATH", tmp_path / "iocs.db")
    monkeypatch.setattr(store_ioc, "_ioc_db", None)

    assert store_ioc.get_ioc_exclusivity("10.0.0.1") is None
    store_ioc.record_ioc_exclusivity("10.0.0.1", "shared")
    assert store_ioc.get_ioc_exclusivity("10.0.0.1") == "shared"

    # Upsert overwrites rather than erroring on a duplicate key
    store_ioc.record_ioc_exclusivity("10.0.0.1", "dedicated", analyst_verified=True)
    assert store_ioc.get_ioc_exclusivity("10.0.0.1") == "dedicated"


# ---------------------------------------------------------------------------
# agents/cti_enrichment.py
# ---------------------------------------------------------------------------

def test_cti_enrichment_looks_up_known_malicious_ip():
    from agents.cti_enrichment import run_cti_enrichment

    state = {
        "alert_raw": {"source_ip": "185.220.101.45"},
        "alert_category": "impossible_travel",
    }
    result = run_cti_enrichment(state)

    indicators = result["cti_output"]["indicators"]
    assert len(indicators) == 1
    assert indicators[0]["ip"] == "185.220.101.45"
    assert indicators[0]["reputation"] == "malicious"
    assert result["agents_completed"] == ["cti_enrichment"]


def test_cti_enrichment_discounts_confidence_for_shared_infra(monkeypatch):
    import rag.store_ioc as store_ioc
    from agents import cti_enrichment as cti_mod

    monkeypatch.setattr(cti_mod, "get_ioc_exclusivity", lambda ip: "shared")

    state = {"alert_raw": {"source_ip": "185.220.101.45"}, "alert_category": "impossible_travel"}
    result = cti_mod.run_cti_enrichment(state)
    indicator = result["cti_output"]["indicators"][0]

    assert indicator["exclusivity"] == "shared"
    assert indicator["confidence"] == round(0.95 * 0.5, 2)


def test_cti_enrichment_handles_alert_with_no_ips():
    from agents.cti_enrichment import run_cti_enrichment

    state = {"alert_raw": {}, "alert_category": "malware"}
    result = run_cti_enrichment(state)

    assert result["cti_output"]["indicators"] == []
    assert isinstance(result["cti_output"]["cti_context"], list)


def test_cti_enrichment_does_not_touch_sibling_branch_outputs():
    """cti_enrichment must not read log_output/attck_output -- they're
    sibling parallel branches in the same LangGraph superstep and are not
    guaranteed to be populated when this agent runs."""
    import inspect
    from agents import cti_enrichment

    source = inspect.getsource(cti_enrichment)
    assert '"log_output"' not in source
    assert '"attck_output"' not in source


# ---------------------------------------------------------------------------
# agents/attck_mapper.py
# ---------------------------------------------------------------------------

def test_attck_mapper_maps_category_to_techniques():
    from agents.attck_mapper import run_attck_mapper

    state = {"alert_category": "lateral_movement", "triage_output": {"category": "lateral_movement"}}
    result = run_attck_mapper(state)
    output = result["attck_output"]

    assert "T1550.002" in output["technique_ids"]
    assert "lateral-movement" in output["observed_tactics"]
    assert output["kill_chain_position"] > 0
    assert len(output["technique_details"]) == len(output["technique_ids"])
    assert result["agents_completed"] == ["attck_mapper"]


def test_attck_mapper_falls_back_to_triage_category():
    """alert_category may be missing; attck_mapper should still work off
    triage_output.category (both available pre-fan-out)."""
    from agents.attck_mapper import run_attck_mapper

    state = {"triage_output": {"category": "data_exfiltration"}}
    result = run_attck_mapper(state)
    assert result["attck_output"]["technique_ids"], "expected non-empty techniques from triage_output.category"


def test_attck_mapper_unknown_category_returns_empty_but_valid_output():
    from agents.attck_mapper import run_attck_mapper

    state = {"alert_category": "totally_unknown"}
    result = run_attck_mapper(state)
    output = result["attck_output"]

    assert output["technique_ids"] == []
    assert output["observed_tactics"] == []
    assert output["kill_chain_position"] == 0
    assert output["predicted_next"] == []


def test_attck_mapper_does_not_touch_sibling_branch_outputs():
    import inspect
    from agents import attck_mapper

    source = inspect.getsource(attck_mapper)
    assert '"log_output"' not in source
    assert '"cti_output"' not in source
