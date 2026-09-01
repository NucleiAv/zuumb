import pathlib

from sqlmodel import select

from app.db.models import Alert
from app.db.session import get_session
from app.ingestion.wazuh_client import ingest, load_alerts, normalize_alert

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
