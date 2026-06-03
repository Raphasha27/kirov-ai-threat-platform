from datetime import datetime
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class ThreatCreate(BaseModel):
    source_ip: str
    event_type: str
    severity: str
    title: str
    description: str
    raw_log: dict
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    risk_score: float = 0.0
    status: str = "new"
    detected_at: datetime | None = None


class ThreatResponse(BaseModel):
    id: int
    source_ip: str
    event_type: str
    severity: str
    title: str
    description: str
    raw_log: dict
    mitre_technique_id: str | None
    mitre_tactic: str | None
    risk_score: float
    status: str
    ai_classification: str | None
    ai_summary: str | None
    detected_at: datetime
    created_at: datetime


class ThreatListResponse(BaseModel):
    items: list[ThreatResponse]
    total: int
    page: int
    page_size: int


class AlertCreate(BaseModel):
    threat_id: int
    rule_name: str
    rule_id: str
    severity: str
    message: str


class AlertResponse(BaseModel):
    id: int
    threat_id: int
    rule_name: str
    rule_id: str
    severity: str
    message: str
    acknowledged: bool
    acknowledged_by: int | None
    acknowledged_at: datetime | None
    created_at: datetime


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str
    threat_ids: list[int]
    assigned_to: int | None = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    threat_ids: list
    assigned_to: int | None
    timeline: list
    playbook: str | None
    ai_analysis: str | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class DashboardSummary(BaseModel):
    total_threats: int
    active_alerts: int
    open_incidents: int
    risk_score: float


class ThreatTrend(BaseModel):
    date: str
    count: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class MITRECoverage(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    count: int


class ThreatStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(new|investigating|resolved|dismissed)$")


class IncidentUpdate(BaseModel):
    status: str | None = None
    assigned_to: int | None = None


class TimelineEvent(BaseModel):
    action: str
    description: str
    user_id: int | None = None
    metadata: dict = {}


class AlertAcknowledge(BaseModel):
    user_id: int


class SilenceRule(BaseModel):
    rule_id: str | None = None
    source: str | None = None
