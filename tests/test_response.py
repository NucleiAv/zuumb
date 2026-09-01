import json
from datetime import datetime

import pytest
from sqlmodel import select

from app.db.models import Alert, Incident, IncidentAlert, Task
from app.db.session import get_session
from app.response import playbooks
from app.response.playbooks import approve_task, propose_for_incident, suggest


def _alert(techs=(), groups=(), aid=None) -> Alert:
    raw = {"rule": {"mitre": {"id": list(techs)}, "groups": list(groups)}}
    return Alert(id=aid, wazuh_alert_id=f"t{aid}", timestamp=datetime(2026, 8, 28, 14, 0),
                 rule_id="1", rule_description="d", raw_json=json.dumps(raw))


def test_suggest_maps_technique_to_playbook_tasks():
    tasks = suggest(1, [_alert(["T1059"], aid=1)], {})
    titles = {t.title for t in tasks}
    assert "Isolate the affected host from the network" in titles
    assert {t.type for t in tasks} == {"mitigation", "investigation"}
    assert all(t.incident_id == 1 and t.status == "todo" for t in tasks)


def test_suggest_dedupes_and_reads_verdict_technique():
    tasks = suggest(7, [_alert(["T1190"], aid=1), _alert([], aid=2)], {2: "T1190"})
    titles = [t.title for t in tasks]
    assert len(titles) == len(set(titles)) == 2  # two T1190 playbooks, once each


def test_suggest_fallback_only_when_attack_group_present():
    fb = "Triage the alert, confirm scope, and document findings"
    assert [t.title for t in suggest(1, [_alert([], ["attack"], aid=1)], {})] == [fb]
    assert suggest(1, [_alert([], ["syslog"], aid=1)], {}) == []


def test_propose_for_incident_persists_and_is_idempotent():
    with get_session() as s:
        a = _alert(["T1110"])
        s.add(a)
        s.commit()
        s.refresh(a)
        inc = Incident(title="db-01", severity="medium")
        s.add(inc)
        s.commit()
        s.refresh(inc)
        s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        s.commit()

        first = propose_for_incident(inc.id, s)
        assert first and all(t.id for t in first)
        assert len(propose_for_incident(inc.id, s)) == len(first)  # rerun -> no dups
        assert len(s.exec(select(Task).where(Task.incident_id == inc.id)).all()) == len(first)


def test_approve_task_changes_only_status():
    with get_session() as s:
        t = Task(incident_id=99, type="mitigation", title="x", priority="high")
        s.add(t)
        s.commit()
        s.refresh(t)
        fixed = (t.incident_id, t.type, t.title, t.priority, t.assignee)
        out = approve_task(s, t.id)
    assert out.status == "done"
    assert (out.incident_id, out.type, out.title, out.priority, out.assignee) == fixed


def test_approve_missing_task_raises():
    with get_session() as s, pytest.raises(ValueError):
        approve_task(s, 123456)


def test_module_has_no_execution_primitives():
    src = open(playbooks.__file__, encoding="utf-8").read()
    banned = ["subprocess", "os.system", "os.popen", "Popen", "pty.spawn", "socket.",
              "import httpx", "import requests", "urllib.request", "eval(", " exec(", "__import__("]
    hits = [b for b in banned if b in src]
    assert hits == [], f"response layer must not execute anything; found {hits}"
