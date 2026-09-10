import pathlib

from sqlmodel import select

from app.db.models import Alert, DeadLetter
from app.db.session import get_session
from app.ingestion.wazuh_client import ingest, ingest_alerts, load_alerts, normalize_alert

DATA = pathlib.Path(__file__).parents[1] / "data" / "synthetic_alerts" / "batch01.jsonl"


def test_normalize_maps_core_fields():
    raw = next(r for r in load_alerts(DATA) if r["id"] == "1787926040.100004")
    a = normalize_alert(raw)
    assert a.wazuh_alert_id == "1787926040.100004"
    assert a.rule_id == "5715"
    assert a.rule_description.startswith("sshd: authentication success")
    assert a.agent_name == "web-01"
    assert a.src_ip == "203.0.113.44"
    assert a.user == "www-data"
    assert a.timestamp.hour == 14


def test_normalize_reads_windows_user_path():
    raw = next(r for r in load_alerts(DATA) if r["id"] == "1787915753.100010")
    assert normalize_alert(raw).user == "jsmith"


def test_ingest_writes_then_dedupes():
    assert ingest(DATA) == 14
    assert ingest(DATA) == 0  # same alerts, nothing new
    with get_session() as s:
        assert len(s.exec(select(Alert)).all()) == 14


def test_malformed_alert_is_quarantined_not_fatal():
    good = {"id": "ok1", "timestamp": "2026-08-28T14:00:00.000+0000",
            "rule": {"id": "5715", "description": "d"}, "agent": {"name": "h"}}
    bad = {"id": "broken1", "timestamp": "2026-08-28T14:01:00.000+0000"}  # no rule -> KeyError
    assert ingest_alerts([bad, good, dict(good, id="ok2")]) == 2  # the bad one didn't abort the batch
    with get_session() as s:
        assert len(s.exec(select(Alert)).all()) == 2
        dl = s.exec(select(DeadLetter)).all()
        assert len(dl) == 1 and dl[0].source == "ingest" and dl[0].key == "broken1"

    ingest_alerts([bad])            # still bad next poll -> attempts bumped, still no crash
    with get_session() as s:
        assert s.exec(select(DeadLetter)).one().attempts == 2
