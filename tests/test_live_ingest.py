"""Phase 12 live-polling path — fixture-driven, no real HTTP / no real LLM."""
from datetime import datetime

from sqlmodel import select

from app.db.models import Alert, Incident, Verdict
from app.db.session import get_session
from app.ingestion.wazuh_client import fetch_alerts_since, ingest_alerts, poll_once
from app.pipeline import run_pipeline_cycle, triage_pending


def _wazuh_alert(aid: str, ts: str, rule_id="5715", desc="sshd: authentication success.",
                 host="web-01", srcip="10.0.0.9"):
    return {"id": aid, "timestamp": ts, "rule": {"id": rule_id, "description": desc},
            "agent": {"name": host}, "data": {"srcip": srcip, "srcuser": "deploy"},
            "full_log": "Accepted password for deploy", "location": "/var/log/auth.log"}


class _FakeResp:
    def __init__(self, sources): self._sources = sources
    def raise_for_status(self): pass
    def json(self):
        return {"hits": {"hits": [{"_source": s} for s in self._sources]}}


class _FakeClient:
    """Records the last request; returns whatever alerts pass the `timestamp` range."""
    def __init__(self, alerts): self.alerts, self.last_body = alerts, None
    def post(self, url, json):
        self.last_body = json
        rng = json["query"].get("range", {}).get("timestamp", {}).get("gt")
        keep = [a for a in self.alerts if rng is None or a["timestamp"] > rng]
        return _FakeResp(sorted(keep, key=lambda a: a["timestamp"]))


def test_fetch_alerts_since_builds_search_and_unwraps_source():
    alerts = [_wazuh_alert("a1", "2026-08-28T14:00:00.000+0000"),
              _wazuh_alert("a2", "2026-08-28T15:00:00.000+0000")]
    fc = _FakeClient(alerts)
    since = datetime(2026, 8, 28, 14, 30)
    out = fetch_alerts_since(since, client=fc)
    assert [a["id"] for a in out] == ["a2"]                       # range filter applied
    assert fc.last_body["query"]["range"]["timestamp"]["gt"].startswith("2026-08-28T14:30")
    assert fc.last_body["sort"] == [{"timestamp": "asc"}]


def test_fetch_alerts_since_none_is_match_all():
    fc = _FakeClient([_wazuh_alert("a1", "2026-08-01T00:00:00.000+0000")])
    assert len(fetch_alerts_since(None, client=fc)) == 1
    assert fc.last_body["query"] == {"match_all": {}}


def test_ingest_alerts_dedupes():
    rows = [_wazuh_alert("d1", "2026-08-28T14:00:00.000+0000"),
            _wazuh_alert("d1", "2026-08-28T14:00:00.000+0000"),  # dup id
            _wazuh_alert("d2", "2026-08-28T14:05:00.000+0000")]
    assert ingest_alerts(rows) == 2
    assert ingest_alerts(rows) == 0


def test_poll_once_uses_max_timestamp_as_cursor():
    seed = [_wazuh_alert("p1", "2026-08-28T14:00:00.000+0000"),
            _wazuh_alert("p2", "2026-08-28T15:00:00.000+0000"),
            _wazuh_alert("p3", "2026-08-28T16:00:00.000+0000")]
    fc = _FakeClient(seed)

    assert poll_once(client=fc) == 3                              # empty DB -> match_all
    assert fc.last_body["query"] == {"match_all": {}}

    assert poll_once(client=fc) == 0                              # cursor now at p3's ts
    assert fc.last_body["query"]["range"]["timestamp"]["gt"].startswith("2026-08-28T16:00")

    fc.alerts.append(_wazuh_alert("p4", "2026-08-28T17:00:00.000+0000"))
    assert poll_once(client=fc) == 1
    with get_session() as s:
        assert len(s.exec(select(Alert)).all()) == 4


def _benign(system, user):
    return {"verdict": "benign", "confidence": 0.5, "reasoning": "x", "mitre_technique": None}


def test_run_pipeline_cycle_polls_triages_correlates_and_stitches():
    fc = _FakeClient([
        _wazuh_alert("c1", "2026-08-28T14:00:00.000+0000", rule_id="31103",
                     desc="SQL injection attempt.", host="web-01", srcip="203.0.113.44"),
        _wazuh_alert("c2", "2026-08-28T14:05:00.000+0000", rule_id="92657",
                     desc="Netcat listener opened.", host="web-01", srcip="203.0.113.44"),
    ])
    mal = lambda s, u: {"verdict": "malicious", "confidence": 0.9,  # noqa: E731
                        "reasoning": "x", "mitre_technique": "T1190"}
    res = run_pipeline_cycle(call=mal, client=fc)
    assert res == {"ingested": 2, "triaged": 2}
    with get_session() as s:
        assert len(s.exec(select(Verdict)).all()) == 2
        incs = s.exec(select(Incident)).all()
        assert incs and incs[0].severity == "high"  # both malicious -> worst = high

    assert run_pipeline_cycle(call=mal, client=fc) == {"ingested": 0, "triaged": 0}


def test_triage_pending_only_hits_untriaged():
    ingest_alerts([_wazuh_alert("t1", "2026-08-28T14:00:00.000+0000")])
    with get_session() as s:
        assert triage_pending(s, call=_benign) == 1
        assert triage_pending(s, call=_benign) == 0
