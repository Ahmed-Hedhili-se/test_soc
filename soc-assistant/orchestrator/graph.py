"""
orchestrator/graph.py

LangGraph StateGraph for the SOC investigation pipeline.

Routing logic:
  - impossible_travel  ->  [cti_enrichment, attck_mapper]  (skip log investigator)
  - all other alerts   ->  [log_investigator, cti_enrichment, attck_mapper]
"""
from __future__ import annotations

import yaml
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from state.investigation import SOCInvestigationState
from agents.triage         import run_triage_agent
from agents.log_investigator import run_log_investigator
from agents.cti_enrichment   import run_cti_enrichment
from agents.attck_mapper      import run_attck_mapper
from agents.synthesis         import run_synthesis
from agents.report_generator  import run_report_generator


# -- Side-channel notification stub (replace with WebSocket in production) --
def _push_fast_path_alert(state: SOCInvestigationState) -> None:
    print(
        f"[FAST-PATH] High-severity alert {state.get('alert_id')} "
        "dispatched via preliminary side-channel."
    )


# -- Threshold loader ---------------------------------------------------------
def _load_fast_path_thresholds() -> tuple[float, float]:
    try:
        with open("config/thresholds.yaml", "r") as f:
            cfg = yaml.safe_load(f)["fast_path"]
        return float(cfg["min_severity"]), float(cfg["min_confidence"])
    except Exception:
        return 9.0, 0.90


# -- Conditional router --------------------------------------------------------
def route_after_triage(state: SOCInvestigationState) -> list[str]:
    """
    Fan-out router executed after triage completes.
    Returns a list of node names to run in parallel.
    """
    triage   = state.get("triage_output") or {}
    severity = triage.get("severity", 0.0)
    category = triage.get("category", "")

    # Fast-path side-channel notification
    min_sev, min_conf = _load_fast_path_thresholds()
    if severity >= min_sev and state.get("confidence_score", 0.0) >= min_conf:
        _push_fast_path_alert(state)

    # Identity-only: skip log investigator (no endpoint telemetry available)
    if category == "impossible_travel":
        return ["cti_enrichment", "attck_mapper"]

    # Default: parallel log investigation + CTI enrichment + ATT&CK mapping
    return ["log_investigator", "cti_enrichment", "attck_mapper"]


# -- Node wrapper ---------------------------------------------------------------
def agent_node_wrapper(func):
    """
    Wraps an agent function so that:
      1. It receives a copy of the state (safe for parallel execution)
      2. Returns only the DELTA of keys that changed, regardless of whether
         `func` itself returns a partial update or the full mutated state --
         this makes the wrapper robust to either agent-authoring style,
         and specifically prevents the class of bug where a node returning
         the full state causes an Annotated[list, operator.add] channel
         (e.g. agents_completed) to have its already-accumulated contents
         re-added on top of themselves by every downstream node.
      3. For append-reducer list fields, returns only the newly added items
         (never re-includes items already present before this node ran).
      4. On failure, retries once, then records to missing_evidence and
         agents_failed rather than propagating the exception.
    """
    _APPEND_KEYS = frozenset(
        {"agents_completed", "agents_activated", "agents_failed",
         "audit_log", "missing_evidence"}
    )

    def wrapper(state: dict) -> dict:
        before = dict(state)

        def _run():
            return func(dict(state))

        try:
            after = _run()
        except Exception:
            try:
                after = _run()          # retry(1)
            except Exception:
                agent_name = func.__name__.replace("run_", "")
                return {
                    "missing_evidence": [f"{agent_name}: failed after retry"],
                    "agents_failed": [agent_name],
                }

        # Compute delta
        diff: dict = {}
        for key, new_val in after.items():
            old_val = before.get(key)
            if new_val == old_val:
                continue
            if key in _APPEND_KEYS:
                old_list = old_val or []
                new_list = new_val or []
                delta    = [item for item in new_list if item not in old_list]
                if delta:
                    diff[key] = delta
            else:
                diff[key] = new_val
        return diff

    wrapper.__name__ = func.__name__
    return wrapper


# -- Graph builder ----------------------------------------------------------------
def build_soc_graph() -> StateGraph:
    """
    Compile and return the SOC investigation LangGraph.

    Topology:
        triage  ->  [log_investigator | cti_enrichment | attck_mapper]  ->  reasoning_synthesis  ->  report_generator
    """
    graph = StateGraph(SOCInvestigationState)

    graph.add_node("triage",              agent_node_wrapper(run_triage_agent))
    graph.add_node("log_investigator",    agent_node_wrapper(run_log_investigator))
    graph.add_node("cti_enrichment",      agent_node_wrapper(run_cti_enrichment))
    graph.add_node("attck_mapper",        agent_node_wrapper(run_attck_mapper))
    graph.add_node("reasoning_synthesis", agent_node_wrapper(run_synthesis))
    graph.add_node("report_generator",    agent_node_wrapper(run_report_generator))

    # Entry point
    graph.set_entry_point("triage")

    # Conditional fan-out
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "log_investigator": "log_investigator",
            "cti_enrichment": "cti_enrichment",
            "attck_mapper": "attck_mapper"
        }
    )

    # All parallel branches converge at synthesis
    graph.add_edge("log_investigator",    "reasoning_synthesis")
    graph.add_edge("cti_enrichment",      "reasoning_synthesis")
    graph.add_edge("attck_mapper",        "reasoning_synthesis")

    # Linear tail
    graph.add_edge("reasoning_synthesis", "report_generator")
    graph.add_edge("report_generator",    END)

    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)
