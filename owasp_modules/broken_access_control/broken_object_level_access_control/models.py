from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class PathParam(BaseModel):
    name: str
    required: bool
    schema: Dict[str, Any]

class Endpoint(BaseModel):
    method: str
    path: str
    params: List[PathParam]
    description: Optional[str]

class BolaVuln(BaseModel):
    endpoint: str
    method: str
    risk_level: str #(high, medium, low)
    details: str
    evidence: Optional[str]

class SequentialIDAlert(BaseModel):
    path: str
    param_name: str
    details: str




