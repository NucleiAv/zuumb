"""Advisory-only incident similarity (app/correlation/similarity.py). Uses a
deterministic fake embedding instead of the real model, no network call, no
ONNX download, same principle as the LLM's `call=` injection: fast, offline,
still exercising the real cosine-similarity code path."""
from datetime import datetime

from sqlmodel import select

from app.correlation import similarity as sim
from app.db.models import Alert, Incident, IncidentAlert, IncidentSimilarity, Verdict
from app.db.session import get_session
from tests.conftest import FakeEmbedding as _FakeEmbedding


def _seed_incident(host, ip, rule_description, severity="high", n=1):
    with get_session() as s:
        alerts = []
        for i in range(n):
            a = Alert(wazuh_alert_id=f"{host}-{ip}-{i}", timestamp=datetime(2026, 1, 1),
                     rule_id="1", rule_description=rule_description,
                     agent_name=host, src_ip=ip, raw_json='{"rule":{"groups":["attack"]}}')
            s.add(a); s.commit(); s.refresh(a)
            s.add(Verdict(alert_id=a.id, verdict="malicious", confidence=0.9,
                          reasoning_text="x", model_version="t"))
            alerts.append(a)
        s.commit()
        inc = Incident(title=host, severity=severity)
        s.add(inc); s.commit(); s.refresh(inc)
        s.add_all(IncidentAlert(incident_id=inc.id, alert_id=a.id) for a in alerts)
        s.commit()
        return inc.id


def test_incident_brief_excludes_entities_keeps_rule_descriptions():
    with get_session() as s:
        a = Alert(wazuh_alert_id="x", timestamp=datetime(2026, 1, 1), rule_id="1",
                 rule_description="SQL injection attempt", agent_name="web-01",
                 src_ip="203.0.113.44", user="www-data", raw_json="{}")
        brief = sim._incident_brief([a])
    assert "SQL injection attempt" in brief
    assert "web-01" not in brief and "203.0.113.44" not in brief and "www-data" not in brief


def test_find_similar_flags_a_pair_with_no_shared_entity_but_similar_text(monkeypatch):
    monkeypatch.setattr(sim, "_model", lambda: _FakeEmbedding())
    monkeypatch.setattr(sim.settings, "similarity_threshold", 0.5)
    a = _seed_incident("host-a", "203.0.113.1", "web shell script uploaded to web root")
    b = _seed_incident("host-b", "203.0.113.2", "web shell script uploaded to web root")
    with get_session() as s:
        pairs = sim.find_similar(s)
    ids = {(p[0], p[1]) for p in pairs}
    assert (min(a, b), max(a, b)) in ids


def test_find_similar_skips_a_pair_that_shares_an_entity_even_if_identical_text(monkeypatch):
    """Same host -> already the deterministic engine's / chain stitcher's job;
    surfacing it here too would just be noise."""
    monkeypatch.setattr(sim, "_model", lambda: _FakeEmbedding())
    monkeypatch.setattr(sim.settings, "similarity_threshold", 0.5)
    a = _seed_incident("shared-host", "203.0.113.1", "web shell script uploaded to web root")
    b = _seed_incident("shared-host", "203.0.113.2", "web shell script uploaded to web root")
    with get_session() as s:
        pairs = sim.find_similar(s)
    ids = {(p[0], p[1]) for p in pairs}
    assert (min(a, b), max(a, b)) not in ids


def test_find_similar_does_not_flag_unrelated_incidents(monkeypatch):
    monkeypatch.setattr(sim, "_model", lambda: _FakeEmbedding())
    monkeypatch.setattr(sim.settings, "similarity_threshold", 0.5)
    _seed_incident("host-a", "203.0.113.1", "web shell script uploaded to web root")
    _seed_incident("host-b", "203.0.113.2", "scheduled backup job completed successfully")
    with get_session() as s:
        pairs = sim.find_similar(s)
    assert pairs == []


def test_find_similar_needs_at_least_two_candidate_incidents(monkeypatch):
    monkeypatch.setattr(sim, "_model", lambda: _FakeEmbedding())
    _seed_incident("host-a", "203.0.113.1", "web shell script uploaded to web root")
    with get_session() as s:
        assert sim.find_similar(s) == []


def test_refresh_persists_and_is_idempotent(monkeypatch):
    monkeypatch.setattr(sim, "_model", lambda: _FakeEmbedding())
    monkeypatch.setattr(sim.settings, "similarity_threshold", 0.5)
    a = _seed_incident("host-a", "203.0.113.1", "web shell script uploaded to web root")
    b = _seed_incident("host-b", "203.0.113.2", "web shell script uploaded to web root")

    rows = sim.refresh()
    assert len(rows) == 1 and {rows[0].incident_a_id, rows[0].incident_b_id} == {a, b}

    rows_again = sim.refresh()  # rebuild from scratch, not append
    with get_session() as s:
        assert len(s.exec(select(IncidentSimilarity)).all()) == len(rows_again) == 1


def test_for_incident_reads_either_side_of_the_pair_sorted_by_score(monkeypatch):
    monkeypatch.setattr(sim, "_model", lambda: _FakeEmbedding())
    monkeypatch.setattr(sim.settings, "similarity_threshold", 0.3)
    a = _seed_incident("host-a", "203.0.113.1", "web shell script uploaded to web root")
    b = _seed_incident("host-b", "203.0.113.2", "web shell uploaded")
    c = _seed_incident("host-c", "203.0.113.3", "web shell script uploaded to the web root here")
    sim.refresh()
    with get_session() as s:
        hits = sim.for_incident(s, a)
    assert {h["incident"].id for h in hits} == {b, c}
    assert hits[0]["score"] >= hits[1]["score"]
