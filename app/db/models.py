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
    mitre_techniques: str | None = None  # native rule.mitre.id, comma-joined; preferred over the LLM guess
    raw_json: str  # original Wazuh alert, verbatim


class Verdict(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    alert_id: int = Field(foreign_key="alert.id", index=True)
    verdict: str  # benign | suspicious | malicious  <- the PRIMARY verdict (LLM)
    confidence: float  # 0..1
    reasoning_text: str
    mitre_technique: str | None = None
    model_version: str
    created_at: datetime = Field(default_factory=_now)
    # D3: a cheap local TF-IDF second opinion, advisory only. Nullable so the
    # mini-migration adds it; drives nothing (severity/correlation ignore it).
    second_opinion: str | None = None              # benign | suspicious | malicious
    second_opinion_confidence: float | None = None


class Incident(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    status: str = "open"  # open | investigating | closed
    severity: str = "low"  # low | medium | high
    created_at: datetime = Field(default_factory=_now)


class IncidentAlert(SQLModel, table=True):
    incident_id: int = Field(foreign_key="incident.id", primary_key=True)
    alert_id: int = Field(foreign_key="alert.id", primary_key=True)


class AttackChain(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    # open | investigating | contained | closed  -> workflow state
    # confirmed-narrative | false-chain           -> analyst's causation call (item 5)
    status: str = "open"
    created_at: datetime = Field(default_factory=_now)
    # System-computed at stitch time (item 2). Nullable so the mini-migration can
    # add them to an existing DB; stitch() rewrites every chain each cycle anyway.
    confidence: str | None = "medium"          # high | medium | low
    confidence_reasons: str | None = ""        # "; "-joined caveats, empty when high


class AttackChainIncident(SQLModel, table=True):
    attack_chain_id: int = Field(foreign_key="attackchain.id", primary_key=True)
    incident_id: int = Field(foreign_key="incident.id", primary_key=True)
    stage_order: int  # 0-based position in MITRE tactic kill-chain order
    tactic: str | None = "Unknown"             # this stage's representative tactic
    tactic_source: str | None = "unknown"      # native (Wazuh rule.mitre.tactic) | fallback (guessed) | unknown


class Task(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="incident.id", index=True)
    type: str  # investigation | mitigation
    title: str
    status: str = "todo"  # todo | in_progress | done | failed (live dispatch rejected)
    priority: str = "medium"  # low | medium | high
    # Phase 14: set only on tasks that map to an allowlisted active-response action.
    action: str | None = None          # block-ip | disable-user  (see app/response/active_response.py)
    action_target: str | None = None   # the IP / username the action needs
    agent_id: str | None = None        # Wazuh agent id to dispatch against


class ResponseActionLog(SQLModel, table=True):
    """Audit trail — every approved active-response dispatch (dry-run included)."""
    id: int | None = Field(default=None, primary_key=True)
    task_id: int = Field(foreign_key="task.id", index=True)
    incident_id: int = Field(foreign_key="incident.id", index=True)
    action: str
    target: str
    agent_id: str
    dry_run: bool
    approver: str = "analyst"
    ok: bool = False
    status_code: int | None = None
    response_text: str = ""
    created_at: datetime = Field(default_factory=_now)


class AnalystFeedback(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    verdict_id: int = Field(foreign_key="verdict.id", index=True)
    analyst_verdict: str  # benign | suspicious | malicious
    note: str = ""
    created_at: datetime = Field(default_factory=_now)


class DeadLetter(SQLModel, table=True):
    """A record that failed to process. One row per (source, key); `attempts`
    counts retries. Keeps a poison alert or model response from stalling the
    pipeline — once attempts hits the cap, that record is skipped for good."""
    id: int | None = Field(default=None, primary_key=True)
    source: str = Field(index=True)  # ingest | triage
    key: str = Field(index=True)     # wazuh_alert_id (ingest) or str(alert.id) (triage)
    error: str = ""
    attempts: int = 1
    created_at: datetime = Field(default_factory=_now)


class Credential(SQLModel, table=True):
    """Single-row (id=1) override for the .env dashboard login. Present only after
    the user sets their own credentials from the Settings page; while it exists,
    settings.dashboard_password is ignored for login."""
    id: int | None = Field(default=1, primary_key=True)
    username: str
    pw_hash: str  # pbkdf2_hmac(sha256) hex
    pw_salt: str  # hex
    updated_at: datetime = Field(default_factory=_now)
