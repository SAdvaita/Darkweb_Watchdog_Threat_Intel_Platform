import hashlib
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Asset(SQLModel, table=True):
    __tablename__ = "assets"
    id: Optional[int] = Field(default=None, primary_key=True)
    type: str  # domain, subdomain, ip, email_pattern, vendor, person
    value: str
    criticality: int = Field(default=3)  # 1-5
    owner: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class RawItem(SQLModel, table=True):
    __tablename__ = "raw_items"
    id: Optional[int] = Field(default=None, primary_key=True)
    source: str
    url: str = ""
    fetched_at: datetime = Field(default_factory=_utcnow)
    fingerprint: str = ""
    redacted_text: str = ""
    data_origin: str = "live"  # live, replay, canary


class Finding(SQLModel, table=True):
    __tablename__ = "findings"
    id: Optional[int] = Field(default=None, primary_key=True)
    raw_item_id: Optional[int] = Field(default=None, foreign_key="raw_items.id")
    rule_id: str = ""
    category: str = ""
    severity: str = "low"
    confidence: float = 0.0
    score: float = 0.0
    score_breakdown: str = "{}"  # JSON string
    asset_id: Optional[int] = Field(default=None, foreign_key="assets.id")
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    sightings: int = Field(default=1)
    status: str = "new"  # new, triage, containing, remediated, closed, false_positive
    title: str = ""
    description: str = ""
    attack_techniques: str = "[]"  # JSON list


class Case(SQLModel, table=True):
    __tablename__ = "cases"
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    status: str = "new"
    severity: str = "medium"
    sla_ack_due: Optional[datetime] = None
    sla_contain_due: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    assignee: str = ""


class CaseFinding(SQLModel, table=True):
    __tablename__ = "case_findings"
    case_id: int = Field(foreign_key="cases.id", primary_key=True)
    finding_id: int = Field(foreign_key="findings.id", primary_key=True)


class Canary(SQLModel, table=True):
    __tablename__ = "canaries"
    id: Optional[int] = Field(default=None, primary_key=True)
    type: str  # gist, certificate, repo
    marker: str
    location_url: str = ""
    planted_at: datetime = Field(default_factory=_utcnow)
    first_detected_at: Optional[datetime] = None
    detected_source: str = ""
    time_to_detect_seconds: Optional[float] = None


class GraphEdge(SQLModel, table=True):
    __tablename__ = "edges"
    id: Optional[int] = Field(default=None, primary_key=True)
    src_type: str
    src_id: str
    relation: str
    dst_type: str
    dst_id: str
    weight: float = 1.0


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_log"
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_utcnow)
    actor: str = "system"
    action: str
    detail: str = "{}"  # JSON
    prev_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        payload = f"{self.ts}|{self.actor}|{self.action}|{self.detail}|{self.prev_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()


class Metric(SQLModel, table=True):
    __tablename__ = "metrics"
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_utcnow)
    name: str
    value: float
    labels: str = "{}"  # JSON


class SourceHealth(SQLModel, table=True):
    __tablename__ = "source_health"
    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(unique=True)
    last_success: Optional[datetime] = None
    last_error: Optional[datetime] = None
    last_error_msg: str = ""
    items_fetched: int = 0
    errors_total: int = 0
