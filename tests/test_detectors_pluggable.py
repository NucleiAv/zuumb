"""D2 checkpoint: two independently-built detectors (D1 auth-log anomaly, D2
network beacon) both flow through zuumb's UNMODIFIED triage + correlation, and
land in one incident when they relate. If this file ever needs a change in
`app/`, the schema-normalization boundary is wrong — fix the detector, not core.
"""
from datetime import datetime, timedelta

from sqlmodel import select

from app.correlation.engine import correlate
from app.db.models import Alert, Incident, IncidentAlert, Verdict
from app.db.session import get_session
from app.pipeline import triage_pending
from app.triage.offline import offline_verdict
from detectors.authlog import FeatureRow, ScoredWindow, window_to_alert
from detectors.ingest import ingest_with_retry
from detectors.netflow import Conn, beacon_to_alert, find_beacons

_T0 = datetime(2026, 9, 10, 12, 0, 0)


def _d1_alert(host):
    row = FeatureRow(host=host, window_start=_T0, n_events=180, n_distinct_templates=1,
                     events_per_min=36.0, template_counts={1: 180})
    return window_to_alert(ScoredWindow(row=row, score=18.0, z=5.2, is_anomaly=True))


def _d2_alert(host, src_ip="10.0.0.5", dst_ip="45.61.10.9"):
    conns = [Conn(_T0 + timedelta(seconds=i * 60), src_ip, dst_ip, 443) for i in range(20)]
    return beacon_to_alert(find_beacons(conns)[0], host=host)


def test_core_ingests_a_d2_alert_with_no_code_changes():
    assert ingest_with_retry([_d2_alert("web-01")]) == 1
    with get_session() as s:
        a = s.exec(select(Alert).where(Alert.rule_id == "901001")).one()
        assert a.agent_name == "web-01" and a.dst_ip == "45.61.10.9"


def test_d1_and_d2_alerts_on_the_same_host_land_in_one_incident():
    # a brute-force-ish auth anomaly AND a C2 beacon, both seen on web-01
    n = ingest_with_retry([_d1_alert("web-01"), _d2_alert("web-01")])
    assert n == 2

    with get_session() as s:
        triage_pending(s, call=offline_verdict)   # unmodified
        correlate(session=s)                      # unmodified

        by_rule = {a.rule_id: a.id for a in s.exec(select(Alert)).all()}
        d1_id, d2_id = by_rule["900001"], by_rule["901001"]
        links = {la.alert_id: la.incident_id
                 for la in s.exec(select(IncidentAlert)).all() if la.alert_id in (d1_id, d2_id)}
        assert links[d1_id] == links[d2_id], "same host -> same incident"

        inc = s.get(Incident, links[d1_id])
        assert "web-01" in inc.title
        # both got a verdict from the same unmodified triage path
        assert {v.alert_id for v in s.exec(select(Verdict)).all()} >= {d1_id, d2_id}


def test_unrelated_d1_and_d2_alerts_do_not_share_an_incident():
    ingest_with_retry([_d1_alert("web-01"), _d2_alert("db-09", src_ip="10.9.9.9", dst_ip="8.8.4.4")])
    with get_session() as s:
        triage_pending(s, call=offline_verdict)
        correlate(session=s)
        by_rule = {a.rule_id: a.id for a in s.exec(select(Alert)).all()}
        links = {la.alert_id: la.incident_id for la in s.exec(select(IncidentAlert)).all()}
        assert links[by_rule["900001"]] != links[by_rule["901001"]]
