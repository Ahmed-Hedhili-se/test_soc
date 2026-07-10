from pydantic import BaseModel
from typing import List, Optional

class SynthesisOutput(BaseModel):
    verdict: str
    confidence: float
    narrative: str
    remediation_required: bool
    escalation_reason: Optional[str] = None
    missing_evidence: List[str] = []
