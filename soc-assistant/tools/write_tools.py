from pydantic import BaseModel

class IsolateHostInput(BaseModel):
    hostname: str
    justification: str
    approved_by: str          # REQUIRED — only HITL interface populates this

def isolate_host(input: IsolateHostInput) -> dict:
    """Isolate host via EDR API. Requires analyst approval."""
    if not input.approved_by:
        raise PermissionError("approved_by field required. Use HITL interface.")
    # Call EDR API here
    pass
