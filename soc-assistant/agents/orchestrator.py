from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from state.investigation import SOCInvestigationState
from agents.triage import run_triage_agent
# Import other agent functions here as they are developed
def run_log_agent(state): return state
def run_cti_agent(state): return state
def run_attck_agent(state): return state
def run_synthesis_agent(state): return state
def run_report_agent(state): return state
def run_hitl_node(state): return state

def route_after_triage(state: SOCInvestigationState) -> list[str]:
    """Dynamic routing based on alert category and severity."""
    severity = state["triage_output"]["severity"]
    category = state["alert_category"]

    # Low severity — skip to report directly
    if severity < 3.0:
        return ["report_generator"]

    # Fast path for critical active attacks
    if severity >= 9.0 and state["confidence_score"] >= 0.90:
        return ["fast_path_alert"]

    # Impossible travel — no endpoint logs needed
    if category == "impossible_travel":
        return ["cti_enrichment", "attck_mapper"]

    # Default — full pipeline
    return ["log_investigator", "cti_enrichment", "attck_mapper"]

def build_soc_graph():
    graph = StateGraph(SOCInvestigationState)

    # Add all agent nodes
    graph.add_node("triage",             run_triage_agent)
    graph.add_node("log_investigator",   run_log_agent)
    graph.add_node("cti_enrichment",     run_cti_agent)
    graph.add_node("attck_mapper",       run_attck_agent)
    graph.add_node("reasoning_synthesis",run_synthesis_agent)
    graph.add_node("report_generator",   run_report_agent)
    graph.add_node("hitl_interface",     run_hitl_node)

    # Entry point
    graph.set_entry_point("triage")

    # Dynamic routing after triage
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "log_investigator": "log_investigator",
            "cti_enrichment": "cti_enrichment",
            "attck_mapper": "attck_mapper",
            "report_generator": "report_generator",
            "fast_path_alert": "hitl_interface" # Added to prevent errors
        }
    )

    # All parallel agents converge to synthesis
    graph.add_edge("log_investigator",  "reasoning_synthesis")
    graph.add_edge("cti_enrichment",    "reasoning_synthesis")
    graph.add_edge("attck_mapper",      "reasoning_synthesis")

    # Sequential: synthesis → report → HITL
    graph.add_edge("reasoning_synthesis", "report_generator")
    graph.add_edge("report_generator",    "hitl_interface")
    graph.add_edge("hitl_interface",       END)

    # Persist state to SQLite for crash recovery
    checkpointer = SqliteSaver.from_conn_string("./soc_state.db")
    return graph.compile(checkpointer=checkpointer)
