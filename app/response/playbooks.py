"""Response layer: propose human playbook tasks for an incident.

PROPOSES only. Nothing here executes — a proposed task is just a DB row. A task
whose playbook maps to an allowlisted active-response action is tagged with
`action` / `action_target` / `agent_id` here; the dispatch (after a human
approves) happens in app.response.approve -> app.response.active_response.
tests/test_response.py enforces that this module stays execution-free.
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from app.db.models import Alert, IncidentAlert, Task, Verdict
from app.db.session import get_session, init_db

# Static templates. A template fires when the incident's alerts carry any of its
# `techniques` (ATT&CK id) or any of its rule `groups`.
PLAYBOOKS: list[dict] = [
    {"techniques": {"T1190"}, "type": "mitigation", "priority": "high",
     "title": "Virtual-patch the exploited endpoint and add a WAF rule for the payload"},
    {"techniques": {"T1190"}, "type": "investigation", "priority": "high",
     "title": "Review web/app logs for successful exploitation and dropped web shells"},
    {"techniques": {"T1059"}, "type": "mitigation", "priority": "high",
     "title": "Isolate the affected host from the network"},
    {"techniques": {"T1059"}, "type": "investigation", "priority": "high",
     "title": "Capture the process tree and outbound connections for the shell"},
    {"techniques": {"T1078"}, "type": "mitigation", "priority": "high",
     "title": "Rotate or disable the affected account credential",
     "action": "disable-user", "needs": "user"},
    {"techniques": {"T1078", "T1110"}, "type": "investigation", "priority": "medium",
     "title": "Review auth logs for other sessions from the same source IP"},
    {"techniques": {"T1110"}, "type": "mitigation", "priority": "medium",
     "title": "Block the source IP at the perimeter and enforce account lockout",
     "action": "block-ip", "needs": "ip"},
    {"techniques": {"T1041"}, "type": "mitigation", "priority": "high",
     "title": "Block egress to the destination and preserve the transferred data"},
    {"techniques": {"T1041"}, "type": "investigation", "priority": "high",
     "title": "Determine what data was transferred and its sensitivity"},
    {"techniques": {"T1595"}, "type": "investigation", "priority": "low",
     "title": "Correlate the scanning source with any later activity"},
]

_FALLBACK = {"type": "investigation", "priority": "medium",
             "title": "Triage the alert, confirm scope, and document findings"}


def _signal_alerts(alerts: list[Alert], verdict_by_alert: dict[int, str]) -> list[Alert]:
    """The alerts that carry an attack signal (non-benign verdict or an `attack`
    rule group). Falls back to all alerts when none stand out."""
    return [
        a for a in alerts
        if verdict_by_alert.get(a.id) in ("malicious", "suspicious")
        or "attack" in json.loads(a.raw_json).get("rule", {}).get("groups", [])
    ] or alerts


def _resolve_action(need: str, signal: list[Alert]) -> tuple[str, str] | None:
    """(target, agent_id) for one action, both taken from a SINGLE alert so the
    target is never paired with an agent that never observed it. `need` is
    'ip' or 'user'. None when no single alert carries both."""
    for a in signal:
        target = a.src_ip if need == "ip" else a.user
        agent = json.loads(a.raw_json).get("agent", {}).get("id")
        if target and agent:
            return target, agent
    return None


def _signals(alerts: list[Alert], technique_by_alert: dict[int, str | None]) -> tuple[set[str], set[str]]:
    techniques: set[str] = set()
    groups: set[str] = set()
    for a in alerts:
        raw = json.loads(a.raw_json)
        rule = raw.get("rule", {})
        techniques.update(rule.get("mitre", {}).get("id", []) or [])
        groups.update(rule.get("groups", []) or [])
        tech = technique_by_alert.get(a.id)
        if tech:
            techniques.add(tech)
    return techniques, groups


def suggest(incident_id: int, alerts: list[Alert], technique_by_alert: dict[int, str | None],
            verdict_by_alert: dict[int, str] | None = None) -> list[Task]:
    """Proposed (unsaved) Task rows for one incident. Pure — no DB, no side effects."""
    techniques, groups = _signals(alerts, technique_by_alert)
    signal = _signal_alerts(alerts, verdict_by_alert or {})
    seen: set[str] = set()
    tasks: list[Task] = []
    for pb in PLAYBOOKS:
        if pb["techniques"] & techniques and pb["title"] not in seen:
            seen.add(pb["title"])
            task = Task(incident_id=incident_id, type=pb["type"],
                        title=pb["title"], priority=pb["priority"])
            if pb.get("action"):
                resolved = _resolve_action(pb["needs"], signal)
                if resolved:
                    task.action = pb["action"]
                    task.action_target, task.agent_id = resolved
            tasks.append(task)
    if not tasks and "attack" in groups:
        tasks.append(Task(incident_id=incident_id, **_FALLBACK))
    return tasks


def propose_for_incident(incident_id: int, session: Session | None = None) -> list[Task]:
    """Persist any suggested task not already stored for the incident. Idempotent.
    Returns all of the incident's tasks."""
    init_db()
    own = session is None
    session = session or get_session()
    try:
        alert_ids = [
            link.alert_id
            for link in session.exec(
                select(IncidentAlert).where(IncidentAlert.incident_id == incident_id)
            ).all()
        ]
        alerts = session.exec(select(Alert).where(Alert.id.in_(alert_ids))).all()
        verdict_rows = session.exec(
            select(Verdict).where(Verdict.alert_id.in_(alert_ids))
        ).all()
        technique = {v.alert_id: v.mitre_technique for v in verdict_rows}
        verdict = {v.alert_id: v.verdict for v in verdict_rows}
        existing = {
            t.title for t in session.exec(select(Task).where(Task.incident_id == incident_id)).all()
        }
        for task in suggest(incident_id, alerts, technique, verdict):
            if task.title not in existing:
                session.add(task)
        session.commit()
        return session.exec(
            select(Task).where(Task.incident_id == incident_id).order_by(Task.id)
        ).all()
    finally:
        if own:
            session.close()
