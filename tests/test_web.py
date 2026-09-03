from datetime import datetime

import json

from fastapi.testclient import TestClient
from sqlmodel import select

from app.db.models import (
    Alert,
    AnalystFeedback,
    AttackChain,
    AttackChainIncident,
    Incident,
    IncidentAlert,
    Task,
    Verdict,
)
from app.db.session import get_session
from app.main import app

client = TestClient(app)


def _seed() -> tuple[int, int]:
    with get_session() as s:
        a = Alert(wazuh_alert_id="w1", timestamp=datetime(2026, 8, 28, 14, 0), rule_id="31103",
                  rule_description="SQL injection attempt.", agent_name="web-01",
                  src_ip="203.0.113.44", user="www-data", raw_json="{}")
        s.add(a)
        s.commit()
        s.refresh(a)
        s.add(Verdict(alert_id=a.id, verdict="malicious", confidence=0.9,
                      reasoning_text="clear exploit payload", model_version="test"))
        inc = Incident(title="web-01 (1 alert)", severity="high")
        s.add(inc)
        s.commit()
        s.refresh(inc)
        s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        s.commit()
        return inc.id, a.id


def test_incidents_list_renders():
    iid, _ = _seed()
    r = client.get("/")
    assert r.status_code == 200
    assert "web-01 (1 alert)" in r.text
    assert f"/incidents/{iid}" in r.text


def test_incidents_list_embeds_charts():
    _seed()
    r = client.get("/")
    assert 'id="c-severity"' in r.text and 'id="c-timeline"' in r.text
    assert 'id="c-mitre"' in r.text
    assert "/static/chart.umd.min.js" in r.text
    assert "window.STATS" in r.text


def test_bar_click_filter_narrows_incident_list():
    # two incidents on different hosts
    with get_session() as s:
        for h in ("web-01", "db-01"):
            a = Alert(wazuh_alert_id=f"w-{h}", timestamp=datetime(2026, 8, 28, 14, 0),
                      rule_id="1", rule_description="d", agent_name=h, raw_json="{}")
            s.add(a); s.commit(); s.refresh(a)
            inc = Incident(title=h, severity="low")
            s.add(inc); s.commit(); s.refresh(inc)
            s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id)); s.commit()

    allr = client.get("/").text
    assert ">web-01<" in allr and ">db-01<" in allr
    filtered = client.get("/?host=web-01").text
    assert "filtered by" in filtered and "host = web-01" in filtered
    assert ">web-01<" in filtered and ">db-01<" not in filtered


def test_pages_have_breadcrumb_and_widget_chrome():
    iid, _ = _seed()
    home = client.get("/").text
    assert 'class="breadcrumb"' in home
    assert ">Dashboards<" in home and 'class="here">Incidents<' in home
    assert home.count('class="card-menu"') == 8  # 7 charts + heatmap
    assert home.count('data-stat=') == 8

    # KPI summary cards (item 5) + activity heatmap (item 6, cells rendered client-side in local tz)
    assert 'class="kpis"' in home and home.count('class="kpi') == 5  # section + 4 cards
    assert "Total alerts" in home and "Hosts affected" in home
    assert 'href="/?severity=high"' in home              # High-severity card -> filtered list
    assert 'id="c-heatmap"' in home and 'class="heatmap"' in home

    detail = client.get(f"/incidents/{iid}").text
    assert 'class="breadcrumb"' in detail
    assert f'class="here">#{iid}<' in detail


def test_incident_detail_shows_alert_and_verdict():
    iid, _ = _seed()
    r = client.get(f"/incidents/{iid}")
    assert r.status_code == 200
    assert "SQL injection attempt." in r.text
    assert "malicious" in r.text
    assert "clear exploit payload" in r.text


def test_incident_detail_missing_is_404():
    assert client.get("/incidents/999999").status_code == 404


def test_incident_rows_link_to_alert_detail():
    iid, aid = _seed()
    html = client.get(f"/incidents/{iid}").text
    assert f'<tr data-href="/alerts/{aid}">' in html


def test_alert_detail_renders_raw_data_and_stored_reasoning_only():
    import json as _json
    with get_session() as s:
        raw = _json.dumps({"rule": {"id": "5715", "description": "sshd: auth ok",
                                    "mitre": {"id": ["T1078"]}},
                           "agent": {"name": "db-01"}, "data": {"srcip": "10.0.0.9"}})
        a = Alert(wazuh_alert_id="ad1", timestamp=datetime(2026, 8, 28, 14, 0), rule_id="5715",
                  rule_description="sshd: auth ok", agent_name="db-01", src_ip="10.0.0.9", raw_json=raw)
        s.add(a); s.commit(); s.refresh(a)
        s.add(Verdict(alert_id=a.id, verdict="suspicious", confidence=0.55,
                      reasoning_text="Service account login from an unusual subnet.",
                      model_version="claude-haiku-4-5", mitre_technique="T1078"))
        s.commit()
        aid = a.id

    html = client.get(f"/alerts/{aid}").text
    # Section A — raw, verbatim, "not present" for absent fields
    assert "Section A" in html and "Section B" in html
    assert "rule.description" in html and "data.srcip" in html and "10.0.0.9" in html
    assert "not present in source" in html          # dst_ip / user are null
    assert "raw_json (verbatim)" in html
    # Section B — exactly the stored reasoning, labelled AI
    assert "AI-generated triage reasoning" in html
    assert "Service account login from an unusual subnet." in html
    assert "claude-haiku-4-5" in html
    assert client.get("/alerts/999999").status_code == 404


def _seed_incident_with_technique(tech="T1059") -> int:
    with get_session() as s:
        raw = json.dumps({"rule": {"mitre": {"id": [tech]}, "groups": ["attack"]}})
        a = Alert(wazuh_alert_id=f"tk-{tech}", timestamp=datetime(2026, 8, 28, 14, 9),
                  rule_id="92657", rule_description="Netcat listener opened.",
                  agent_name="web-01", raw_json=raw)
        s.add(a)
        s.commit()
        s.refresh(a)
        inc = Incident(title="web-01", severity="high")
        s.add(inc)
        s.commit()
        s.refresh(inc)
        s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        s.commit()
        return inc.id


def test_incident_detail_lists_response_tasks_with_approve():
    iid = _seed_incident_with_technique("T1059")
    html = client.get(f"/incidents/{iid}").text
    assert "Response tasks" in html
    assert "Isolate the affected host from the network" in html
    assert 'action="/tasks/' in html and "Approve" in html
    assert "DRY-RUN" in html and "nothing reaches a host" in html  # dry-run is the default


def test_approve_task_marks_done_and_redirects():
    iid = _seed_incident_with_technique("T1110")
    client.get(f"/incidents/{iid}")  # viewing the incident proposes its tasks
    with get_session() as s:
        task = s.exec(select(Task).where(Task.incident_id == iid)).first()
    r = client.post(f"/tasks/{task.id}/approve", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/incidents/{iid}"
    with get_session() as s:
        assert s.get(Task, task.id).status == "done"
    assert client.post("/tasks/999999/approve").status_code == 404


def test_action_task_dry_run_logs_and_shows_in_audit():
    from app.db.models import ResponseActionLog
    with get_session() as s:
        raw = json.dumps({"rule": {"mitre": {"id": ["T1110"]}, "groups": ["attack"]},
                          "agent": {"id": "001", "name": "edge-01"}})
        a = Alert(wazuh_alert_id="ar1", timestamp=datetime(2026, 8, 28, 14, 0), rule_id="5712",
                  rule_description="brute force", src_ip="203.0.113.9", raw_json=raw)
        s.add(a); s.commit(); s.refresh(a)
        s.add(Verdict(alert_id=a.id, verdict="malicious", confidence=0.9,
                      reasoning_text="x", model_version="t"))
        inc = Incident(title="edge-01", severity="high")
        s.add(inc); s.commit(); s.refresh(inc)
        s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id)); s.commit()
        iid = inc.id

    detail = client.get(f"/incidents/{iid}").text
    assert "block-ip" in detail and "203.0.113.9" in detail  # action tag on the task
    with get_session() as s:
        tid = s.exec(select(Task).where(Task.incident_id == iid, Task.action == "block-ip")).one().id

    r = client.post(f"/tasks/{tid}/approve", follow_redirects=False)
    assert r.status_code == 303
    with get_session() as s:
        log = s.exec(select(ResponseActionLog)).one()
        assert log.dry_run is True and log.ok is True and log.target == "203.0.113.9"
    audit = client.get("/audit").text
    assert "Response audit (1)" in audit and "block-ip" in audit and "dry-run" in audit


def test_incident_detail_has_verdict_override_form():
    iid, aid = _seed()
    html = client.get(f"/incidents/{iid}").text
    assert 'action="/verdicts/' in html and "override" in html
    assert 'name="analyst_verdict"' in html


def test_verdict_override_records_feedback_and_redirects():
    iid, aid = _seed()
    with get_session() as s:
        vid = s.exec(select(Verdict).where(Verdict.alert_id == aid)).first().id
    r = client.post(f"/verdicts/{vid}/override",
                    data={"analyst_verdict": "benign", "note": "known scanner"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/incidents/{iid}"
    with get_session() as s:
        fb = s.exec(select(AnalystFeedback).where(AnalystFeedback.verdict_id == vid)).first()
    assert fb.analyst_verdict == "benign" and fb.note == "known scanner"

    assert client.post("/verdicts/999999/override", data={"analyst_verdict": "benign"}).status_code == 404
    assert client.post(f"/verdicts/{vid}/override", data={"analyst_verdict": "nope"}).status_code == 400
    assert 'class="v-benign"' in client.get(f"/incidents/{iid}").text  # analyst override now shown


def test_override_recomputes_incident_severity_with_analyst_verdict():
    # incident with two alerts: one malicious (-> high), one benign
    with get_session() as s:
        inc = Incident(title="web-01", severity="low")
        s.add(inc); s.commit(); s.refresh(inc)
        vids = {}
        for tag, verd in (("mal", "malicious"), ("ben", "benign")):
            a = Alert(wazuh_alert_id=f"sev-{tag}", timestamp=datetime(2026, 8, 28, 14, 0),
                      rule_id="1", rule_description="d", agent_name="web-01", raw_json="{}")
            s.add(a); s.commit(); s.refresh(a)
            v = Verdict(alert_id=a.id, verdict=verd, confidence=0.9, reasoning_text="x", model_version="t")
            s.add(v); s.commit(); s.refresh(v)
            s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id)); s.commit()
            vids[tag] = v.id
        iid = inc.id

    # JSON path returns the new severity; downgrading the malicious verdict -> low
    r = client.post(f"/verdicts/{vids['mal']}/override",
                    data={"analyst_verdict": "benign"}, headers={"Accept": "application/json"})
    assert r.status_code == 200
    assert r.json() == {"analyst_verdict": "benign", "severity": "low"}
    with get_session() as s:
        assert s.get(Incident, iid).severity == "low"

    # overriding the other alert up to malicious -> incident back to high
    r = client.post(f"/verdicts/{vids['ben']}/override",
                    data={"analyst_verdict": "malicious"}, headers={"Accept": "application/json"})
    assert r.json()["severity"] == "high"
    with get_session() as s:
        assert s.get(Incident, iid).severity == "high"


def test_topnav_and_chains_pages_render():
    home = client.get("/").text
    assert 'href="/chains"' in home and 'class="topnav"' in home

    empty = client.get("/chains")
    assert empty.status_code == 200 and "No attack chains" in empty.text

    with get_session() as s:
        c = AttackChain(title="2 stages: Reconnaissance -> Exfiltration")
        s.add(c)
        s.commit()
        s.refresh(c)
        inc = Incident(title="web-01", severity="high")
        s.add(inc)
        s.commit()
        s.refresh(inc)
        s.add(AttackChainIncident(attack_chain_id=c.id, incident_id=inc.id, stage_order=0))
        s.commit()
        cid = c.id

    lst = client.get("/chains").text
    assert "Reconnaissance" in lst and "<th>Severity</th>" in lst and "<th>Status</th>" in lst
    detail = client.get(f"/chains/{cid}")
    assert detail.status_code == 200 and "web-01" in detail.text
    assert 'class="killchain"' in detail.text and 'class="chain-timeline' in detail.text  # items 1 & 3
    assert 'action="/chains/' in detail.text and 'name="status"' in detail.text  # item 4
    assert 'class="chain-timeline few"' in detail.text  # 1-stage seed -> "few" centering modifier
    assert client.get("/chains/999999").status_code == 404


def test_chain_status_update():
    with get_session() as s:
        c = AttackChain(title="t")
        s.add(c)
        s.commit()
        s.refresh(c)
        cid = c.id
    r = client.post(f"/chains/{cid}/status", data={"status": "contained"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/chains/{cid}"
    with get_session() as s:
        assert s.get(AttackChain, cid).status == "contained"
    assert client.post(f"/chains/{cid}/status", data={"status": "bogus"}).status_code == 400
    assert client.post("/chains/999999/status", data={"status": "open"}).status_code == 404


def _seed_two_days():
    """web-01 incident on Fri 14:00, db-01 incident on Sat 09:00, distinct techniques."""
    ids = {}
    with get_session() as s:
        for host, ts, rid, tech in [
            ("web-01", datetime(2026, 8, 28, 14, 0), "31103", "T1190"),
            ("db-01", datetime(2026, 8, 29, 9, 0), "5715", "T1078"),
        ]:
            a = Alert(wazuh_alert_id=f"td-{host}", timestamp=ts, rule_id=rid,
                      rule_description="d", agent_name=host, raw_json="{}")
            s.add(a); s.commit(); s.refresh(a)
            s.add(Verdict(alert_id=a.id, verdict="suspicious", confidence=0.5,
                          reasoning_text="x", model_version="t", mitre_technique=tech))
            inc = Incident(title=host, severity="low")
            s.add(inc); s.commit(); s.refresh(inc)
            s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id)); s.commit()
            ids[host] = inc.id
    return ids


def test_verdict_distribution_panel_present():
    _seed()
    html = client.get("/").text
    assert 'id="c-verdicts"' in html and 'data-stat="verdict_dist"' in html
    assert '"verdict_dist"' in html  # embedded in window.STATS


def test_timeline_panel_is_double_width_with_zoom():
    html = client.get("/").text
    assert 'class="card wide-2"' in html               # item 1: timeline gets 2 columns
    assert '/static/chartjs-plugin-zoom.min.js' in html  # item 2: zoom plugin loaded
    assert 'class="link-btn zoom-reset" type="button" data-chart="c-timeline"' in html
    # verdict panel comes before the timeline card now (row 1 vs row 2)
    assert html.index('id="c-verdicts"') < html.index('id="c-timeline"')


def test_time_range_and_custom_dates_filter():
    _seed_two_days()  # incidents on 2026-08-28 and 2026-08-29
    assert client.get("/").text.count('/incidents/') >= 2         # all
    # client sends explicit UTC instants (computed from the viewer's local range)
    only28 = client.get("/?from=2026-08-28T00:00:00Z&to=2026-08-28T23:59:59Z").text
    assert ">web-01<" in only28 and ">db-01<" not in only28
    assert 'class="chip on"' in client.get("/?range=7d").text     # range chip reflects state


def test_created_column_sort_toggles():
    ids = _seed_two_days()
    desc = client.get("/").text            # default: newest first
    asc = client.get("/?sort=created&dir=asc").text
    # web-01 (older) comes before db-01 (newer) only when asc
    assert asc.index(f"/incidents/{ids['web-01']}") < asc.index(f"/incidents/{ids['db-01']}")
    assert desc.index(f"/incidents/{ids['db-01']}") < desc.index(f"/incidents/{ids['web-01']}")
    assert "dir=asc" in desc and "dir=desc" in asc  # header link offers the opposite


def test_mitre_and_heatmap_cell_filters():
    ids = _seed_two_days()
    by_tech = client.get("/?mitre=T1190").text
    assert ">web-01<" in by_tech and ">db-01<" not in by_tech
    # 2026-08-28 is a Friday (weekday 4), the web-01 alert is at hour 14
    by_cell = client.get("/?dow=4&hour=14").text
    assert ">web-01<" in by_cell and ">db-01<" not in by_cell
    # local-tz shift: the same alert lands in the previous hour's cell for a viewer at UTC+... no,
    # tzmin is minutes to ADD to local for UTC, so UTC-60 (tzmin=-60) puts 14:00 UTC at 15:00 local
    assert ">web-01<" in client.get("/?dow=4&hour=15&tzmin=-60").text
    assert 'id="c-heatmap"' in client.get("/").text       # cells rendered client-side into this


def test_severity_and_verdict_donut_filters():
    _seed_two_days()  # both incidents seeded "low"; verdicts: web-01 & db-01 both "suspicious"
    with get_session() as s:
        inc = s.exec(select(Incident).where(Incident.title == "web-01")).one()
        inc.severity = "high"
        s.commit()
    hi = client.get("/?severity=high").text
    assert ">web-01<" in hi and ">db-01<" not in hi           # severity-donut slice click
    susp = client.get("/?verdict=suspicious").text
    assert ">web-01<" in susp and ">db-01<" in susp           # verdict-donut slice click
    assert client.get("/?verdict=malicious").text.count("/incidents/") == 0
    home = client.get("/").text
    assert home.count('class="kpi') == 5 and home.count('<a class="kpi" href="/">') == 3  # 3 KPIs clear filters



def test_incidents_index_redirects_to_root():
    r = client.get("/incidents", follow_redirects=False)
    assert r.status_code in (307, 308)
    assert r.headers["location"] == "/"


def test_empty_incidents_list_ok():
    r = client.get("/")
    assert r.status_code == 200
    assert "No incidents match" in r.text
