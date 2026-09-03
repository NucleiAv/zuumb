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


# --- execution guard (Phase 14): scoped allowlist, not "no execution ever" -------
# playbooks.py still only proposes; the ONE permitted execution path is
# active_response.py, and it may talk to nothing but the Wazuh AR API.
_NEVER = ["subprocess", "os.system", "os.popen", "Popen", "pty.", "socket.",
          "paramiko", "pexpect", "winrm", "urllib.request", "eval(", " exec(", "__import__("]


def test_playbooks_stays_proposal_only():
    src = open(playbooks.__file__, encoding="utf-8").read()
    hits = [b for b in _NEVER + ["import httpx", "import requests"] if b in src]
    assert hits == [], f"playbooks.py must not execute anything; found {hits}"


def test_active_response_is_scoped_to_the_wazuh_ar_api():
    from app.response import active_response
    src = open(active_response.__file__, encoding="utf-8").read()

    hits = [b for b in _NEVER if b in src]
    assert hits == [], f"active_response.py may only call the AR API; found {hits}"

    # httpx is allowed here — but only pointed at the configured AR API, no other URLs
    import re
    urls = re.findall(r"https?://[^\"'\s)]+", src)
    assert urls == [], f"active_response.py hard-codes a URL: {urls}"
    assert "settings.wazuh_ar_api_url" in src
    # the action set is a fixed dict, not built from input
    assert "ACTIONS: dict[str, dict] = {" in src


def test_dispatch_rejects_actions_outside_the_allowlist():
    from app.response.active_response import dispatch
    with pytest.raises(ValueError):
        dispatch("run-script", "x", "001", client=object())


def test_dispatch_puts_one_ar_call_with_the_mapped_command():
    from app.response import active_response

    class _Resp:
        status_code = 200
        text = '{"data":{"affected_items":["001"]}}'

        def json(self):
            return {"data": {"token": "tok"}}

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self):
            self.calls = []

        def post(self, url, **kw):
            self.calls.append(("POST", url))
            return _Resp()

        def put(self, url, **kw):
            self.calls.append(("PUT", url, kw.get("json")))
            return _Resp()

    c = _Client()
    out = active_response.dispatch("block-ip", "203.0.113.9", "001", client=c)
    assert out == {"ok": True, "status_code": 200, "text": _Resp.text}
    put = next(x for x in c.calls if x[0] == "PUT")
    assert "agents_list=001" in put[1]
    assert put[2]["command"] == "firewall-drop" and put[2]["arguments"] == ["203.0.113.9"]
