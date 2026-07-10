from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class HITLDecision(BaseModel):
    alert_id: str
    action: str           # approve | modify | reject | escalate
    analyst_id: str
    analyst_note: str
    attck_corrections: list[str]  # analyst-corrected technique IDs

@app.post("/hitl/decision")
async def receive_decision(decision: HITLDecision):
    # 1. Log decision to feedback store
    # 2. If approve → dispatch write tools with approved_by field
    # 3. If reject → log FP category, trigger RAG update
    # 4. If modify → log correction pair for future DPO
    # 5. If escalate → forward to Tier 2
    pass

@app.get("/hitl/pending")
async def get_pending_alerts():
    # Return all alerts awaiting analyst decision
    pass
