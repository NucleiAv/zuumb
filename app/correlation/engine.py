"""Correlation: group alerts sharing an entity within a time window into incidents.

`group_alerts` is pure (no DB, no LLM) and carries the logic. `correlate` is the
thin DB wrapper that persists the result.
"""
from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlmodel import Session, delete, select

from app.config import settings
from app.db.models import Alert, Incident, IncidentAlert, Verdict
from app.db.session import get_session, init_db

_SEVERITY = {"benign": "low", "suspicious": "medium", "malicious": "high"}
_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}


def entities(a: Alert) -> set[str]:
    """The host/IP/user identifiers an alert touches."""
    pairs = (("ip", a.src_ip), ("ip", a.dst_ip), ("host", a.agent_name), ("user", a.user))
    return {f"{kind}:{val}" for kind, val in pairs if val}


def group_alerts(alerts: list[Alert], window_minutes: int) -> list[list[Alert]]:
    """Transitively union alerts sharing an entity within `window_minutes`. Pure."""
    alerts = sorted(alerts, key=lambda a: a.timestamp)
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    window = timedelta(minutes=window_minutes)
    for i, a in enumerate(alerts):
        for j in range(i + 1, len(alerts)):
            if alerts[j].timestamp - a.timestamp > window:
                break  # sorted by time: nothing further is in range of i
            if entities(a) & entities(alerts[j]):
                parent[find(i)] = find(j)

    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    return sorted(groups.values(), key=lambda g: g[0].timestamp)


def _title(group: list[Alert]) -> str:
    counts = Counter(e for a in group for e in entities(a))
    top = counts.most_common(1)[0][0] if counts else "unknown"
    return f"{top} ({len(group)} alert{'' if len(group) == 1 else 's'})"


def incident_severity(group: list[Alert], verdicts: dict[int, str]) -> str:
    worst = max((verdicts.get(a.id, "benign") for a in group), key=_RANK.get)
    return _SEVERITY[worst]


def correlate(session: Session | None = None, window_minutes: int | None = None) -> list[Incident]:
    """Rebuild all incidents from the alerts in the DB. Idempotent.

    ponytail: derived-state rebuild — wipes incidents/incident_alerts each run, so
    any analyst status/closed_at is lost. Fine for the batch POC; switch to
    incremental alert->incident assignment when Phase 9's feedback loop needs a
    stable incident identity.
    """
    init_db()
    own = session is None
    session = session or get_session()
    window = window_minutes or settings.correlation_window_minutes
    try:
        alerts = session.exec(select(Alert)).all()
        verdicts = {v.alert_id: v.verdict for v in session.exec(select(Verdict)).all()}

        session.exec(delete(IncidentAlert))
        session.exec(delete(Incident))
        session.commit()

        incidents: list[Incident] = []
        for group in group_alerts(alerts, window):
            inc = Incident(title=_title(group), severity=incident_severity(group, verdicts))
            session.add(inc)
            session.commit()
            session.refresh(inc)
            session.add_all(IncidentAlert(incident_id=inc.id, alert_id=a.id) for a in group)
            session.commit()
            incidents.append(inc)
        return incidents
    finally:
        if own:
            session.close()
