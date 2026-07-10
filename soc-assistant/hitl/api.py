from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict, Any

app = FastAPI()

class HITLDecision(BaseModel):
    action: str           # "approve" | "modify" | "reject" | "escalate"
    analyst_id: str
    modified_fields: Optional[Dict[str, Any]] = None

@app.get("/investigations/{id}")
async def get_investigation_evidence(id: str):
    """Returns evidence chain before the verdict."""
    return {
        "alert_raw": {},
        "log_output": {},
        "cti_output": {},
        "attck_output": {},
        "sla_deadline": "timestamp"
    }

@app.get("/investigations/{id}/reasoning-trace")
async def get_reasoning_trace(id: str):
    """Full synthesis reasoning trace."""
    return {
        "synthesis_output": {}
    }

@app.post("/investigations/{id}/decision")
async def receive_decision(id: str, decision: HITLDecision):
    """Receives analyst decision. Only code path that can populate 'approved_by'."""
    # Log decision
    # If approve -> forward remediation to MCP
    # If modify | reject -> write to feedback/rag_update.py
    
    return {"status": "decision_recorded", "action": decision.action}
