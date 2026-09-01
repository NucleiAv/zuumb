"""SQLModel tables. Grows one phase at a time — see plan Section 5 for the full schema."""
from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    wazuh_alert_id: str = Field(index=True, unique=True)
    timestamp: datetime
    rule_id: str
    rule_description: str
    agent_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    raw_json: str  # original Wazuh alert, verbatim


class Verdict(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    alert_id: int = Field(foreign_key="alert.id", index=True)
    verdict: str  # benign | suspicious | malicious
    confidence: float  # 0..1
    reasoning_text: str
    mitre_technique: str | None = None
    model_version: str
    created_at: datetime = Field(default_factory=_now)


class Incident(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    status: str = "open"  # open | investigating | closed
    severity: str = "low"  # low | medium | high
    created_at: datetime = Field(default_factory=_now)
    closed_at: datetime | None = None


class IncidentAlert(SQLModel, table=True):
    incident_id: int = Field(foreign_key="incident.id", primary_key=True)
    alert_id: int = Field(foreign_key="alert.id", primary_key=True)


class AttackChain(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    status: str = "open"  # open | investigating | contained | closed
    created_at: datetime = Field(default_factory=_now)


class AttackChainIncident(SQLModel, table=True):
    attack_chain_id: int = Field(foreign_key="attackchain.id", primary_key=True)
    incident_id: int = Field(foreign_key="incident.id", primary_key=True)
    stage_order: int  # 0-based position in MITRE tactic kill-chain order


class Task(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="incident.id", index=True)
    type: str  # investigation | mitigation
    title: str
    status: str = "todo"  # todo | in_progress | done
    priority: str = "medium"  # low | medium | high
    assignee: str | None = None


class AnalystFeedback(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    verdict_id: int = Field(foreign_key="verdict.id", index=True)
    analyst_verdict: str  # benign | suspicious | malicious
    note: str = ""
    created_at: datetime = Field(default_factory=_now)
