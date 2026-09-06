from datetime import datetime, timedelta

from sqlmodel import select

from app.correlation.engine import correlate, group_alerts
from app.db.models import Alert, Incident, IncidentAlert, Verdict
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


def test_correlate_severity_is_pending_until_triaged_then_worst_verdict():
    init_db()
    ingest("data/synthetic_alerts/batch01.jsonl")
    incidents = correlate(window_minutes=30)
    # item 10: no verdicts yet -> "pending", not a misleading "low"
    assert {i.severity for i in incidents} == {"pending"}

    with get_session() as s:
        alerts = s.exec(select(Alert)).all()
        for a in alerts:
            s.add(Verdict(alert_id=a.id, verdict="benign", confidence=0.5,
                          reasoning_text="x", model_version="t"))
        s.commit()
    incidents = correlate(window_minutes=30)   # same incidents, updated in place
    assert {i.severity for i in incidents} == {"low"}


def test_correlate_keeps_incident_ids_and_tasks_across_reruns():
    from app.db.models import Task
    init_db()
    ingest("data/synthetic_alerts/batch01.jsonl")
    first = correlate(window_minutes=30)
    ids_before = sorted(i.id for i in first)
    with get_session() as s:
        s.add(Task(incident_id=first[0].id, type="mitigation", title="hand-made",
                   priority="high", status="done"))
        s.commit()

    correlate(window_minutes=30)   # rerun: no delete/recreate
    with get_session() as s:
        assert sorted(i.id for i in s.exec(select(Incident)).all()) == ids_before
        t = s.exec(select(Task)).one()
        assert t.incident_id == first[0].id and t.status == "done"  # survived the rebuild


def test_analyst_override_severity_survives_a_recorrelate():

    from app.feedback.logger import record_override
    init_db()
    ingest("data/synthetic_alerts/batch01.jsonl")
    with get_session() as s:
        a = s.exec(select(Alert)).first()
        v = Verdict(alert_id=a.id, verdict="benign", confidence=0.5,
                    reasoning_text="x", model_version="t")
        s.add(v); s.commit(); s.refresh(v)
    correlate(window_minutes=30)
    with get_session() as s:
        record_override(s, v.id, "malicious", "actually an exploit")
    # item 8: correlate must not overwrite the analyst's call with the model rollup
    for inc in correlate(window_minutes=30):
        aids = None
        with get_session() as s:
            aids = {x.alert_id for x in
                    s.exec(select(IncidentAlert).where(IncidentAlert.incident_id == inc.id)).all()}
        if a.id in aids:
            assert inc.severity == "high"


def test_merge_closes_the_loser_and_moves_its_tasks():
    from app.db.models import Task
    init_db()
    with get_session() as s:
        # two incidents that don't share an entity yet
        a1 = Alert(wazuh_alert_id="m1", timestamp=T0, rule_id="1", rule_description="d",
                   src_ip="1.1.1.1", raw_json="{}")
        a2 = Alert(wazuh_alert_id="m2", timestamp=T0 + timedelta(minutes=2), rule_id="1",
                   rule_description="d", user="bob", raw_json="{}")
        s.add_all([a1, a2]); s.commit()
    incs = {i.title.split()[0]: i.id for i in correlate(window_minutes=30)}
    assert len(incs) == 2
    loser = sorted(incs.values())[1]  # the later-id incident
    with get_session() as s:
        s.add(Task(incident_id=loser, type="mitigation", title="t", priority="high"))
        s.commit()
        # a bridging alert ties both entities together -> one group next correlate
        s.add(Alert(wazuh_alert_id="m3", timestamp=T0 + timedelta(minutes=4), rule_id="1",
                    rule_description="d", src_ip="1.1.1.1", user="bob", raw_json="{}"))
        s.commit()
    correlate(window_minutes=30)
    with get_session() as s:
        assert len(s.exec(select(Incident).where(Incident.status == "open")).all()) == 1
        assert s.get(Incident, loser).status == "merged"
        assert s.exec(select(Task)).one().incident_id != loser  # re-pointed to the survivor


def test_incident_created_at_is_earliest_alert_not_rebuild_time():
    init_db()
    ingest("data/synthetic_alerts/batch01.jsonl")
    correlate(window_minutes=30)
    with get_session() as s:
        for inc in s.exec(select(Incident)).all():
            aids = [x.alert_id for x in
                    s.exec(select(IncidentAlert).where(IncidentAlert.incident_id == inc.id)).all()]
            earliest = min(a.timestamp for a in
                           s.exec(select(Alert).where(Alert.id.in_(aids))).all())
            assert inc.created_at == earliest  # stable across reruns, reflects when it started
