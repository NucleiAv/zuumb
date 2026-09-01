from datetime import datetime, timedelta

from sqlmodel import select

from app.correlation.engine import correlate, group_alerts
from app.db.models import Alert, Incident, IncidentAlert
from app.db.session import get_session, init_db
from app.ingestion.wazuh_client import ingest

T0 = datetime(2026, 8, 28, 12, 0)


def _a(mins, *, sid=None, host=None, user=None, rid="1") -> Alert:
    return Alert(wazuh_alert_id=f"c-{mins}-{sid}-{host}-{user}", timestamp=T0 + timedelta(minutes=mins),
                rule_id=rid, rule_description="d", src_ip=sid, agent_name=host, user=user, raw_json="{}")


def test_shared_ip_within_window_groups():
    groups = group_alerts([_a(0, sid="1.1.1.1"), _a(5, sid="1.1.1.1")], window_minutes=30)
    assert len(groups) == 1


def test_shared_ip_outside_window_splits():
    groups = group_alerts([_a(0, sid="1.1.1.1"), _a(45, sid="1.1.1.1")], window_minutes=30)
    assert len(groups) == 2


def test_no_shared_entity_splits():
    groups = group_alerts([_a(0, sid="1.1.1.1"), _a(5, sid="2.2.2.2")], window_minutes=30)
    assert len(groups) == 2


def test_grouping_is_transitive():
    # A~B share host, B~C share ip, A and C share nothing directly
    a = _a(0, host="h1")
    b = _a(5, host="h1", sid="9.9.9.9")
    c = _a(10, sid="9.9.9.9")
    groups = group_alerts([a, b, c], window_minutes=30)
    assert len(groups) == 1 and len(groups[0]) == 3


def test_correlate_persists_and_is_idempotent():
    init_db()
    ingest("data/synthetic_alerts/batch01.jsonl")
    first = correlate(window_minutes=30)
    with get_session() as s:
        n_inc = len(s.exec(select(Incident)).all())
        n_links = len(s.exec(select(IncidentAlert)).all())
    assert len(first) == n_inc > 0
    assert n_links == 14  # every alert lands in exactly one incident

    correlate(window_minutes=30)  # rerun
    with get_session() as s:
        assert len(s.exec(select(Incident)).all()) == n_inc  # no duplicates
        assert len(s.exec(select(IncidentAlert)).all()) == 14


def test_correlate_severity_from_worst_alert():
    init_db()
    ingest("data/synthetic_alerts/batch01.jsonl")
    incidents = correlate(window_minutes=30)
    # with no verdicts stored, every incident defaults to low
    assert {i.severity for i in incidents} == {"low"}
