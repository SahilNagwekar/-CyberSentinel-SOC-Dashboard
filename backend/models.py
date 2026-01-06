from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime

class Log(BaseModel):
    timestamp: datetime
    source: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    event_type: str
    status: Optional[str] = None
    severity: Optional[str] = "low"
    raw: Optional[Dict] = None
