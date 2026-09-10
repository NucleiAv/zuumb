"""Correlation: group alerts sharing an entity within a time window into incidents.

`group_alerts` is pure (no DB, no LLM) and carries the logic. `correlate` is the
thin DB wrapper that persists the result.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from sqlmodel import Session, delete, select

from app.config import settings
from app.db.models import Alert, AnalystFeedback, Incident, IncidentAlert, Task, Verdict
from app.db.session import get_session, init_db

_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}


def entities(a: Alert) -> set[str]:
    """The host/IP/user identifiers an alert touches."""
    pairs = (("ip", a.src_ip), ("ip", a.dst_ip), ("host", a.agent_name), ("user", a.user))
    return {f"{kind}:{val}" for kind, val in pairs if val}


def techniques_for(a: Alert, guess: str | None = None) -> set[str]:
    """ATT&CK technique ids for an alert: Wazuh's native `rule.mitre.id` when the
    alert carries it, otherwise the triage model's single guess. Native wins."""
    if a.mitre_techniques:
        return {t for t in a.mitre_techniques.split(",") if t}
    return {guess} if guess else set()


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


def incident_severity(group: list[Alert], model_verdicts: dict[int, str],
                      analyst_verdicts: dict[int, str] | None = None) -> str:
    """low | medium | high | pending.

    - An analyst override on an alert wins over the model's verdict (item 8).
    - A confirmed-malicious alert makes the incident `high` regardless.
    - Otherwise, while any constituent alert has no verdict at all, the incident
      is `pending`, not a real severity (item 10) — showing `low` mid-triage
      understates it.
    """
    analyst_verdicts = analyst_verdicts or {}
    ranks: list[int] = []
    untriaged = False
    for a in group:
        v = analyst_verdicts.get(a.id) or model_verdicts.get(a.id)
        if v is None:
            untriaged = True
        else:
            ranks.append(_RANK[v])
    if 2 in ranks:
        return "high"
    if untriaged:
        return "pending"
    return ["low", "medium"][max(ranks, default=0)]  # guard above rules out rank 2


def _analyst_verdicts(session: Session) -> dict[int, str]:
    """alert_id -> the latest analyst override verdict for it, if any."""
    rows = session.exec(
        select(AnalystFeedback, Verdict)
        .join(Verdict, AnalystFeedback.verdict_id == Verdict.id)
        .order_by(AnalystFeedback.created_at, AnalystFeedback.id)
    ).all()
    return {v.alert_id: fb.analyst_verdict for fb, v in rows}  # later rows win


def correlate(session: Session | None = None, window_minutes: int | None = None) -> list[Incident]:
    """Reconcile incidents against the current alert grouping, in place.

    An incident keeps its id across runs, and with it its tasks, status, and
    analyst-set severity (item 7). Each group is matched to the existing incident
    it overlaps most; unmatched groups become new incidents; an existing incident
    whose alerts all moved into a group another incident won is marked `merged`
    and its tasks re-pointed to that winner. Incidents are never deleted, so
    SQLite can't reuse an id under an unrelated task. created_at stays pinned to
    the earliest alert.
    """
    init_db()
    own = session is None
    session = session or get_session()
    window = window_minutes or settings.correlation_window_minutes
    try:
        alerts = session.exec(select(Alert)).all()
        model_v = {v.alert_id: v.verdict for v in session.exec(select(Verdict)).all()}
        analyst_v = _analyst_verdicts(session)

        groups = group_alerts(alerts, window)
        gsets = [{a.id for a in g} for g in groups]

        existing = session.exec(select(Incident).order_by(Incident.id)).all()
        members: dict[int, set[int]] = defaultdict(set)
        for link in session.exec(select(IncidentAlert)).all():
            members[link.incident_id].add(link.alert_id)

        # match each group to at most one existing incident (max alert overlap),
        # groups largest-first so a merged group claims the bigger predecessor.
        owner: dict[int, int] = {}
        taken: set[int] = set()
        for gi in sorted(range(len(groups)), key=lambda k: -len(gsets[k])):
            best, best_ov = None, 0
            for inc in existing:
                if inc.id in taken:
                    continue
                ov = len(members[inc.id] & gsets[gi])
                if ov > best_ov:
                    best, best_ov = inc.id, ov
            if best is not None:
                owner[gi] = best
                taken.add(best)

        survivors: list[Incident] = []
        for gi, group in enumerate(groups):
            sev = incident_severity(group, model_v, analyst_v)
            title = _title(group)
            created = min(a.timestamp for a in group)
            if gi in owner:
                inc = session.get(Incident, owner[gi])
                inc.title, inc.severity, inc.created_at = title, sev, created
            else:
                inc = Incident(title=title, severity=sev, created_at=created)
                session.add(inc)
                session.commit()
                session.refresh(inc)
            session.exec(delete(IncidentAlert).where(IncidentAlert.incident_id == inc.id))
            session.add_all(IncidentAlert(incident_id=inc.id, alert_id=aid) for aid in gsets[gi])
            session.commit()
            survivors.append(inc)

        survivor_ids = {i.id for i in survivors}
        for inc in existing:
            if inc.id in survivor_ids:
                continue
            absorber = next(
                (owner[gi] for gi, s in enumerate(gsets)
                 if members[inc.id] & s and gi in owner),
                None,
            )
            if absorber and absorber != inc.id:
                for t in session.exec(select(Task).where(Task.incident_id == inc.id)).all():
                    t.incident_id = absorber
            inc.status = "merged"
            session.exec(delete(IncidentAlert).where(IncidentAlert.incident_id == inc.id))
            session.commit()

        return survivors
    finally:
        if own:
            session.close()
