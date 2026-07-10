from pydantic import BaseModel
from datetime import datetime
from typing import Literal, Optional

class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    source: Literal["SIEM", "EDR", "Firewall", "Cloud", "Email", "Identity"]
    category: str
    severity_raw: float
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    raw_log: str
