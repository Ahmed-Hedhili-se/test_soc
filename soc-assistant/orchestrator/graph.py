from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from state.investigation import SOCInvestigationState
import yaml

# Stubbing agent imports for now
def run_triage_agent(state): return state
def run_log_investigator(state): return state
def run_cti_enrichment(state): return state
def run_attck_mapper(state): return state
def run_synthesis(state): return state
def run_report_generator(state): return state

# Mocking a side-channel push
def push_to_websocket(msg: dict): pass

def route_after_triage(state: SOCInvestigationState) -> list[str]:
    """Conditional routing based on triage output."""
    triage = state.get("triage_output", {})
    severity = triage.get("severity", 0.0)
    category = triage.get("category", "")
    
    # Load thresholds (assuming loaded statically for now)
    try:
        with open("config/thresholds.yaml", "r") as f:
            thresholds = yaml.safe_load(f)
            min_sev = thresholds["fast_path"]["min_severity"]
            min_conf = thresholds["fast_path"]["min_confidence"]
    except Exception:
        min_sev = 9.0
        min_conf = 0.90

    # Fast-path mode
    if severity >= min_sev and state.get("confidence_score", 0.0) >= min_conf:
        push_to_websocket({"type": "preliminary_alert", "alert": state["alert_raw"]})
    
    # Identity-only alerts skip log investigator
    if category == "impossible_travel":
        return ["cti_enrichment", "attck_mapper"]
    
    # Default path: Parallel log investigation and CTI enrichment
    return ["log_investigator", "cti_enrichment", "attck_mapper"]

# Wrapper for failure recovery
def retry_wrapper(func):
    def wrapper(state):
        try:
            return func(state)
        except Exception:
            try:
                return func(state) # retry(1)
            except Exception as e:
                # Add to missing_evidence
                agent_name = func.__name__.replace("run_", "")
                if "missing_evidence" not in state:
                    state["missing_evidence"] = []
                state["missing_evidence"].append(f"{agent_name}: failed after retry")
                return state
    return wrapper

def build_soc_graph():
    graph = StateGraph(SOCInvestigationState)

    # Add wrapped nodes
    graph.add_node("triage", retry_wrapper(run_triage_agent))
    graph.add_node("log_investigator", retry_wrapper(run_log_investigator))
    graph.add_node("cti_enrichment", retry_wrapper(run_cti_enrichment))
    graph.add_node("attck_mapper", retry_wrapper(run_attck_mapper))
    graph.add_node("reasoning_synthesis", retry_wrapper(run_synthesis))
    graph.add_node("report_generator", retry_wrapper(run_report_generator))

    graph.set_entry_point("triage")

    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "log_investigator": "log_investigator",
            "cti_enrichment": "cti_enrichment",
            "attck_mapper": "attck_mapper"
        }
    )

    # Parallel branches converge
    graph.add_edge("log_investigator", "reasoning_synthesis")
    graph.add_edge("cti_enrichment", "reasoning_synthesis")
    graph.add_edge("attck_mapper", "reasoning_synthesis")

    # Linear end
    graph.add_edge("reasoning_synthesis", "report_generator")
    graph.add_edge("report_generator", END)

    # Note: SQLiteSaver setup might require specific DB paths
    checkpointer = SqliteSaver.from_conn_string("soc_state.db")
    return graph.compile(checkpointer=checkpointer)
