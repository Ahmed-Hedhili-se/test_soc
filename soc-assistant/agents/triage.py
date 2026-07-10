from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from datetime import datetime
from state.investigation import SOCInvestigationState
from tools.readonly_tools import get_asset_record
# Note: get_user_record and check_maintenance_window would need to be imported

# Local Foundation-sec-8B-Instruct via Ollama
triage_llm = ChatOllama(
    model="foundation-sec-8b-instruct",  # pull from Ollama
    temperature=0.1                       # low temp for classification
)

TRIAGE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a SOC triage agent. Analyze the alert and produce:
    1. severity_score: 0.0-10.0
    2. fp_probability: 0.0-1.0
    3. category: one of [credential_access, lateral_movement, exfiltration,
       persistence, privilege_escalation, impossible_travel, malware, other]
    4. reasoning: one sentence explaining your score

    Respond ONLY with valid JSON matching this schema exactly.
    Consider asset criticality, user context, and maintenance windows."""),
    ("human", """Alert: {alert_raw}
    Asset record: {asset_record}
    User record: {user_record}
    Maintenance window active: {maintenance_active}""")
])

def run_triage_agent(state: SOCInvestigationState) -> SOCInvestigationState:
    """Triage agent node for LangGraph."""
    # Tool calls
    asset = get_asset_record(state["alert_raw"].get("host", ""))
    # user = get_user_record(state["alert_raw"].get("user", ""))
    user = {}
    # maint = check_maintenance_window(
    #     state["alert_raw"].get("host", ""),
    #     state["alert_raw"].get("timestamp", "")
    # )
    maint = {"authorized": False}

    # LLM call
    chain = TRIAGE_PROMPT | triage_llm
    result = chain.invoke({
        "alert_raw": state["alert_raw"],
        "asset_record": asset,
        "user_record": user,
        "maintenance_active": maint.get("authorized", False)
    })

    # Parse JSON output safely
    import json
    try:
        output = json.loads(result.content)
    except json.JSONDecodeError:
        output = {"severity": 5.0, "fp_probability": 0.5,
                  "category": "other", "reasoning": "parse error"}

    # Update state
    state["triage_output"] = output
    state["alert_category"] = output.get("category", "other")
    if "agents_completed" not in state: state["agents_completed"] = []
    state["agents_completed"].append("triage")
    if "audit_log" not in state: state["audit_log"] = []
    state["audit_log"].append({
        "t": datetime.now().isoformat(),
        "event": "triage_completed",
        "data": output
    })

    return state
