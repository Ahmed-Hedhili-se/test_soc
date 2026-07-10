# mcp_tools/write/api.py
from pydantic import BaseModel
from fastapi import HTTPException

class WriteActionInput(BaseModel):
    approved_by: str
    target: str
    justification: str

def validate_approval(input_data: WriteActionInput):
    if not input_data.approved_by:
        raise HTTPException(status_code=403, detail="approved_by field is required for write actions. Must be populated by HITL interface.")

def isolateHost(input_data: WriteActionInput):
    validate_approval(input_data)
    pass

def disableUserAccount(input_data: WriteActionInput):
    validate_approval(input_data)
    pass

def blockIPFirewall(input_data: WriteActionInput):
    validate_approval(input_data)
    pass

def createTicket(input_data: WriteActionInput):
    validate_approval(input_data)
    pass
