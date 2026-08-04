"""
tests/test_dpo_pipeline.py

Regression tests for the DPO continual-improvement loop:
  - review/feedback/preference_pairs.py (pair capture)
  - hitl/api.py's /decision endpoint (triggers pair capture on modify/reject)
  - training/dpo_train.py (dataset assembly + graceful degradation --
    the actual DPOTrainer.train() call is NOT exercised here since it
    requires torch/transformers/trl and a real base checkpoint; see that
    module's docstring)

Run from the soc-assistant/ directory:
    pytest tests/test_dpo_pipeline.py -v
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["SOC_ASSISTANT_MOCK_EMBEDDINGS"] = "1"

SYS_PATH = Path(__file__).parent.parent
if str(SYS_PATH) not in sys.path:
    sys.path.insert(0, str(SYS_PATH))
os.chdir(SYS_PATH)

import pytest


# ---------------------------------------------------------------------------
# review/feedback/preference_pairs.py
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_pairs_dir(tmp_path, monkeypatch):
    """Redirect the JSONL pair store to a throwaway directory so tests
    never touch data/dpo_pairs/ in the real repo."""
    import review.feedback.preference_pairs as pp
    monkeypatch.setattr(pp, "_PAIRS_DIR", tmp_path / "dpo_pairs")
    return pp


def test_build_prompt_context_respects_parallel_fanout_boundaries(isolated_pairs_dir):
    pp = isolated_pairs_dir
    state = {
        "alert_id": "A1", "alert_raw": {"x": 1}, "alert_category": "malware",
        "triage_output": {"severity": 9.0},
        "log_output": {"events": ["e1"]},
        "cti_output": {"indicators": ["i1"]},
        "attck_output": {"technique_ids": ["T1"]},
    }
    # attck_mapper may see triage_output, but never its siblings' outputs
    ctx = pp.build_prompt_context("attck_mapper", state)
    assert "triage_output" in ctx
    assert "log_output" not in ctx
    assert "cti_output" not in ctx

    # reasoning_synthesis converges all four
    ctx = pp.build_prompt_context("reasoning_synthesis", state)
    assert ctx["log_output"] == {"events": ["e1"]}
    assert ctx["attck_output"] == {"technique_ids": ["T1"]}


def test_append_and_load_preference_pairs_roundtrip(isolated_pairs_dir):
    pp = isolated_pairs_dir
    pair = pp.build_preference_pair(
        role="triage",
        prompt_context={"alert_id": "A1"},
        rejected_output={"severity": 5.0},
        chosen_output={"severity": 9.0},
        investigation_id="A1", analyst_id="jane", analyst_note="undercalled it",
        action="modify", timestamp="2026-08-04T00:00:00Z",
    )
    pp.append_preference_pair(pair)
    pp.append_preference_pair(pair)

    loaded = pp.load_preference_pairs("triage")
    assert len(loaded) == 2
    assert loaded[0]["chosen"] == {"severity": 9.0}
    assert pp.count_preference_pairs("triage") == 2
    assert pp.load_preference_pairs("nonexistent_role") == []


def test_record_preference_pairs_from_decision_only_emits_changed_roles(isolated_pairs_dir):
    pp = isolated_pairs_dir
    before = {
        "alert_id": "A1", "alert_raw": {}, "alert_category": "malware",
        "triage_output": {"severity": 5.0},
        "attck_output": {"technique_ids": []},
    }
    after = dict(before)
    after["triage_output"] = {"severity": 9.0}  # analyst corrected severity
    # attck_output unchanged -> must NOT produce a pair

    written = pp.record_preference_pairs_from_decision(
        before_state=before, after_state=after,
        investigation_id="A1", analyst_id="jane", action="modify",
        note="bumped severity", timestamp="2026-08-04T00:00:00Z",
    )

    assert len(written) == 1
    assert written[0]["role"] == "triage"
    assert written[0]["rejected"] == {"severity": 5.0}
    assert written[0]["chosen"] == {"severity": 9.0}
    assert pp.count_preference_pairs("triage") == 1
    assert pp.count_preference_pairs("attck_mapper") == 0


def test_record_preference_pairs_from_decision_no_replacement_writes_nothing(isolated_pairs_dir):
    """A bare 'reject' with no modified_fields changes nothing in state,
    so it must not fabricate a (chosen, rejected) pair."""
    pp = isolated_pairs_dir
    state = {"alert_id": "A1", "triage_output": {"severity": 5.0}}

    written = pp.record_preference_pairs_from_decision(
        before_state=state, after_state=dict(state),
        investigation_id="A1", analyst_id="jane", action="reject",
        note="false positive", timestamp="2026-08-04T00:00:00Z",
    )
    assert written == []


# ---------------------------------------------------------------------------
# hitl/api.py wiring
# ---------------------------------------------------------------------------

@pytest.fixture
def hitl_client(tmp_path, monkeypatch):
    import review.feedback.preference_pairs as pp
    import review.feedback.rag_update as ru
    monkeypatch.setattr(pp, "_PAIRS_DIR", tmp_path / "dpo_pairs")
    monkeypatch.setattr(ru, "_FEEDBACK_LOG_PATH", tmp_path / "feedback_log.jsonl")

    from fastapi.testclient import TestClient
    import hitl.api as hitl_api

    hitl_api._investigation_store.clear()
    hitl_api._decision_log.clear()
    hitl_api.register_investigation("INV-1", {
        "alert_id": "INV-1",
        "alert_raw": {"source_ip": "185.220.101.45"},
        "alert_category": "malware",
        "triage_output": {"severity": 5.0, "category": "malware"},
        "synthesis_output": {"verdict": "needs_investigation"},
    })
    return TestClient(hitl_api.app), pp


def test_decision_modify_triggers_both_feedback_loops(hitl_client):
    client, pp = hitl_client
    resp = client.post("/investigations/INV-1/decision", json={
        "action": "modify",
        "analyst_id": "jane",
        "modified_fields": {"triage_output": {"severity": 9.5, "category": "malware"}},
        "corrected_fields": ["triage_output.severity"],
        "note": "Underrated severity",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["dpo_pairs_recorded"] == 1
    assert pp.count_preference_pairs("triage") == 1


def test_decision_approve_triggers_neither_feedback_loop(hitl_client):
    client, pp = hitl_client
    resp = client.post("/investigations/INV-1/decision", json={
        "action": "approve", "analyst_id": "jane",
    })
    assert resp.status_code == 200
    assert "dpo_pairs_recorded" not in resp.json()
    assert pp.count_preference_pairs("triage") == 0


def test_decision_reject_without_replacement_triggers_no_dpo_pairs(hitl_client):
    client, pp = hitl_client
    resp = client.post("/investigations/INV-1/decision", json={
        "action": "reject", "analyst_id": "jane", "note": "false positive",
    })
    assert resp.status_code == 200
    assert resp.json()["dpo_pairs_recorded"] == 0
    assert pp.count_preference_pairs("triage") == 0


# ---------------------------------------------------------------------------
# training/dpo_train.py -- pure-python parts only (no torch required)
# ---------------------------------------------------------------------------

def test_render_prompt_and_completion_are_deterministic_text():
    from training.dpo_train import render_prompt, render_completion

    ctx = {"alert_id": "A1", "alert_category": "malware"}
    p1 = render_prompt("triage", ctx)
    p2 = render_prompt("triage", ctx)
    assert p1 == p2
    assert "triage" in p1.lower()
    assert "A1" in p1

    c = render_completion({"severity": 9.0})
    assert "9.0" in c


def test_build_role_dataset_none_when_no_pairs(monkeypatch, tmp_path):
    import review.feedback.preference_pairs as pp
    import training.dpo_train as dpo_train
    monkeypatch.setattr(pp, "_PAIRS_DIR", tmp_path / "dpo_pairs")

    assert dpo_train.build_role_dataset("triage") is None


def test_build_role_dataset_splits_train_holdout(monkeypatch, tmp_path):
    import review.feedback.preference_pairs as pp
    import training.dpo_train as dpo_train
    monkeypatch.setattr(pp, "_PAIRS_DIR", tmp_path / "dpo_pairs")

    for i in range(10):
        pair = pp.build_preference_pair(
            role="triage", prompt_context={"i": i},
            rejected_output={"severity": 1.0}, chosen_output={"severity": 9.0},
            investigation_id=f"A{i}", analyst_id="jane", analyst_note=None,
            action="modify", timestamp="2026-08-04T00:00:00Z",
        )
        pp.append_preference_pair(pair)

    dataset = dpo_train.build_role_dataset("triage", holdout_fraction=0.2)
    assert dataset is not None
    assert len(dataset.train) + len(dataset.holdout) == 10
    assert len(dataset.holdout) >= 1
    assert all({"prompt", "chosen", "rejected"} <= set(ex.keys()) for ex in dataset.train)


def test_train_role_skips_when_not_enough_pairs(monkeypatch, tmp_path):
    import review.feedback.preference_pairs as pp
    import training.dpo_train as dpo_train
    monkeypatch.setattr(pp, "_PAIRS_DIR", tmp_path / "dpo_pairs")

    result = dpo_train.train_role("triage", dpo_config={
        "min_pairs_per_role": 50,
        "eval_holdout_fraction": 0.1,
        "base_checkpoints": {"triage": "irrelevant"},
    })
    assert result.promoted is False
    assert "Not enough preference pairs" in result.reason
    assert result.checkpoint_path is None
