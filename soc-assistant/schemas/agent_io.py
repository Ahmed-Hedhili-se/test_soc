from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class TriageOutput(BaseModel):
    severity: float
    fp_probability: float
    category: str
    authorized_activity: bool

class LogInvestigatorOutput(BaseModel):
    events: List[Dict[str, Any]]
    entities: Dict[str, List[str]]
    timeline: List[str]
    anomalies: List[str]

class CTIEnrichmentOutput(BaseModel):
    indicators: List[Dict[str, Any]]
    cti_context: List[Dict[str, Any]] = []
    cti_confidence: float = 0.0
    threat_summary: str = ""

class ATTCKMapperOutput(BaseModel):
    technique_ids: List[str]
    kill_chain_position: int
    observed_tactics: List[str]
    predicted_next: List[str]
    technique_details: List[Dict[str, Any]] = []
