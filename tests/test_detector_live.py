"""D1 continuous operation: the Wazuh-alerts-index source, the scheduled pass,
the cursor, and the dashboard liveness signal."""
from datetime import datetime, timedelta

from sqlmodel import select

from app.db.models import Alert, DetectorCursor
from app.db.session import get_session
from app.web.stats import _detector_status
from detectors.authlog import run as d1run
from detectors.authlog.source import fetch_auth_lines

_T0 = datetime(2026, 9, 10, 0, 0, 0)


def _line(dt, user="x", ip="1.2.3.4"):
    return (f"{dt.strftime('%b %d %H:%M:%S')} agent-lab-01 sshd[1]: "
            f"Failed password for invalid user {user} from {ip} port 22 ssh2")


import random as _random

_RNG = _random.Random(3)


class _FakeResp:
    def __init__(self, hits): self._hits = hits
    def raise_for_status(self): pass
    def json(self): return {"hits": {"hits": [{"_source": h} for h in self._hits]}}


class _FakeClient:
    """Returns auth alerts whose `timestamp` passes the query's `gt` filter."""
    def __init__(self, alerts): self.alerts, self.last_body = alerts, None

    def post(self, url, json):
        self.last_body = json
        gt = None
        for clause in json["query"]["bool"]["must"]:
            gt = clause.get("range", {}).get("timestamp", {}).get("gt", gt)
        keep = [a for a in self.alerts if gt is None or a["timestamp"] > gt]
        return _FakeResp(sorted(keep, key=lambda a: a["timestamp"]))


def _alerts(calm_hours=6, burst_at=None):
    """Calm traffic with realistic jitter (3-10 failed logins per 5-min window),
    plus an optional 120-line burst concentrated in one window."""
    out = []
    for w in range(calm_hours * 12):  # 5-min windows
        base = _T0 + timedelta(minutes=w * 5)
        for i in range(_RNG.randint(3, 10)):
            t = base + timedelta(seconds=i * 20 + _RNG.randint(0, 15))
            out.append({"timestamp": t.isoformat(),
                        "full_log": _line(t, ip=f"1.2.3.{_RNG.randint(1, 250)}")})
    if burst_at is not None:
        for i in range(120):
            t = burst_at + timedelta(seconds=i * 2)
            out.append({"timestamp": t.isoformat(), "full_log": _line(t, ip=f"9.9.9.{i % 250}")})
    return out


# --- source ------------------------------------------------------------------

def test_fetch_auth_lines_query_shape_and_gt_filter():
    fc = _FakeClient(_alerts(calm_hours=2))
    lines = fetch_auth_lines(None, client=fc, limit=50)
    must = fc.last_body["query"]["bool"]["must"]
    assert {"term": {"location": "/var/log/auth.log"}} in must
    assert fc.last_body["_source"] == ["timestamp", "full_log"]
    assert all(isinstance(ln, str) and "sshd" in ln for ln in lines)

    since = _T0 + timedelta(minutes=20)
    fetch_auth_lines(since, client=fc)
    rng = [c for c in fc.last_body["query"]["bool"]["must"] if "range" in c][0]
    assert rng["range"]["timestamp"]["gt"] == since.isoformat()
    assert len(fetch_auth_lines(since, client=fc)) < len(fetch_auth_lines(None, client=fc))


def test_fetch_auth_lines_skips_hits_without_full_log():
    fc = _FakeClient([{"timestamp": _T0.isoformat(), "full_log": _line(_T0)},
                      {"timestamp": _T0.isoformat()}])  # no full_log
    assert len(fetch_auth_lines(None, client=fc)) == 1


# --- scheduled pass + cursor ----------------------------------------------

_NOW = _T0 + timedelta(hours=7)


def test_live_once_flags_a_burst_and_creates_a_cursor():
    fc = _FakeClient(_alerts(calm_hours=6, burst_at=_T0 + timedelta(hours=5, minutes=30)))
    r = d1run.live_once(client=fc, now=_NOW, interval_seconds=600)
    assert r["emitted"] == 1 and r["windows"] >= 10

    with get_session() as s:
        cur = s.get(DetectorCursor, "authlog")
        assert cur.last_ts is not None and cur.last_run_at == _NOW
        assert cur.interval_seconds == 600 and cur.alerts_emitted == 1
        assert s.exec(select(Alert).where(Alert.rule_id == "900001")).one()


def test_second_run_advances_the_cursor_and_does_not_re_emit():
    fc = _FakeClient(_alerts(calm_hours=6, burst_at=_T0 + timedelta(hours=5, minutes=30)))
    d1run.live_once(client=fc, now=_NOW, interval_seconds=600)
    with get_session() as s:
        first_cursor = s.get(DetectorCursor, "authlog").last_ts

    r2 = d1run.live_once(client=fc, now=_NOW + timedelta(minutes=10), interval_seconds=600)
    assert r2["emitted"] == 0                       # burst window already scored
    with get_session() as s:
        cur = s.get(DetectorCursor, "authlog")
        assert cur.last_ts >= first_cursor and cur.alerts_emitted == 1
        assert len(s.exec(select(Alert).where(Alert.rule_id == "900001")).all()) == 1


def test_calm_traffic_emits_nothing():
    fc = _FakeClient(_alerts(calm_hours=8))
    assert d1run.live_once(client=fc, now=_NOW, interval_seconds=600)["emitted"] == 0


# --- dashboard liveness signal ------------------------------------------

def test_detector_status_reports_minutes_ago_and_stale_flag():
    now = datetime(2026, 9, 10, 12, 0, 0)
    with get_session() as s:
        s.add(DetectorCursor(detector="authlog", last_run_at=now - timedelta(minutes=4),
                             interval_seconds=600))
        s.add(DetectorCursor(detector="dead", last_run_at=now - timedelta(hours=2),
                             interval_seconds=600))
        s.commit()
        st = {d["name"]: d for d in _detector_status(s, now=now)}
    assert st["authlog"]["stale"] is False and st["authlog"]["minutes_ago"] == 4
    assert st["dead"]["stale"] is True             # 120m > 3 * 10m
