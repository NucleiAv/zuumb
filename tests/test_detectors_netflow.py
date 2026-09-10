"""D2 network-beacon detector: parse -> find_beacons -> emit -> ingest."""
from datetime import datetime, timedelta

from detectors.netflow import (
    Beacon,
    Conn,
    beacon_to_alert,
    find_beacons,
    parse_conn_log,
)
from detectors.netflow.emit import D2_RULE_ID

_T0 = datetime(2026, 9, 10, 0, 0, 0)


def _regular(src, dst, port, n, gap_s, jitter_s=0):
    import random
    rng = random.Random(0)
    return [Conn(_T0 + timedelta(seconds=i * gap_s + rng.randint(-jitter_s, jitter_s) if jitter_s else i * gap_s),
                 src, dst, port) for i in range(n)]


# --- parse --------------------------------------------------------------------

def test_parse_zeek_conn_log_with_fields_header():
    log = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes",
        "1757462400.000000\tCabc\t10.0.0.5\t44001\t45.61.10.9\t443\ttcp\tssl\t512",
        "1757462460.000000\tCdef\t10.0.0.5\t44002\t45.61.10.9\t443\ttcp\tssl\t520",
    ]
    conns = parse_conn_log(log)
    assert len(conns) == 2
    assert conns[0].src_ip == "10.0.0.5" and conns[0].dst_ip == "45.61.10.9"
    assert conns[0].dst_port == 443 and conns[0].proto == "tcp" and conns[0].orig_bytes == 512


def test_parse_headerless_csv_iso_timestamps():
    log = [
        "2026-09-10T00:00:00, 10.0.0.5, 45.61.10.9, 443",
        "2026-09-10T00:01:00, 10.0.0.5, 45.61.10.9, 443, udp, 300",
        "garbage line",
    ]
    conns = parse_conn_log(log)
    assert [c.dst_port for c in conns] == [443, 443]
    assert conns[1].proto == "udp" and conns[1].orig_bytes == 300


# --- beacon detection -------------------------------------------------------

def test_regular_interval_calls_are_flagged_as_a_beacon():
    conns = _regular("10.0.0.5", "45.61.10.9", 443, n=20, gap_s=60)
    beacons = find_beacons(conns)
    assert len(beacons) == 1
    b = beacons[0]
    assert (b.src_ip, b.dst_ip, b.dst_port) == ("10.0.0.5", "45.61.10.9", 443)
    assert b.cv < 0.2 and b.hits == 20 and b.score > 0


def test_jittery_traffic_is_not_a_beacon():
    conns = _regular("10.0.0.5", "45.61.10.9", 443, n=20, gap_s=60, jitter_s=45)
    assert find_beacons(conns) == []


def test_too_few_calls_is_not_a_beacon():
    assert find_beacons(_regular("10.0.0.5", "1.2.3.4", 80, n=4, gap_s=60)) == []


def test_a_short_burst_is_not_a_beacon_even_if_regular():
    # 10 calls 1s apart = perfectly regular but over only 9s, not sustained
    assert find_beacons(_regular("10.0.0.5", "1.2.3.4", 80, n=10, gap_s=1)) == []


# --- emit ------------------------------------------------------------------

def _beacon():
    return find_beacons(_regular("10.0.0.5", "45.61.10.9", 443, n=20, gap_s=60))[0]


def test_beacon_alert_is_accepted_by_normalize_alert():
    from app.ingestion.wazuh_client import normalize_alert
    a = normalize_alert(beacon_to_alert(_beacon(), host="web-01"))
    assert 901001 <= int(a.rule_id) <= 901999
    assert a.agent_name == "web-01"
    assert a.src_ip == "10.0.0.5" and a.dst_ip == "45.61.10.9"
    assert a.wazuh_alert_id.startswith("ml-d2-")


def test_alert_id_is_stable_for_the_same_days_beacon():
    b = _beacon()
    assert beacon_to_alert(b)["id"] == beacon_to_alert(b)["id"]
    # a different destination -> different id
    other = Beacon("10.0.0.5", "9.9.9.9", 443, b.hits, b.mean_gap_seconds, b.cv,
                   b.span_seconds, b.first_ts, b.last_ts, b.score)
    assert beacon_to_alert(other)["id"] != beacon_to_alert(b)["id"]


def test_agent_name_falls_back_to_src_ip_when_no_host_given():
    assert beacon_to_alert(_beacon())["agent"]["name"] == "10.0.0.5"


def test_runner_end_to_end_flags_a_beacon_and_ingests_it():
    from sqlmodel import select
    from app.db.session import get_session
    from app.db.models import Alert
    from detectors.netflow.run import run

    lines = [f"{(_T0 + timedelta(seconds=i * 60)).isoformat()},10.0.0.5,45.61.10.9,443"
             for i in range(30)]
    alerts = run(lines, host="lab-1")
    assert len(alerts) == 1 and alerts[0]["rule"]["id"] == D2_RULE_ID
    with get_session() as s:
        row = s.exec(select(Alert).where(Alert.rule_id == D2_RULE_ID)).one()
        assert row.agent_name == "lab-1" and row.rule_description.startswith("ML: periodic outbound beacon")
    # re-run -> deduped
    assert run(lines, host="lab-1")  # still returns the alert dict
    with get_session() as s:
        assert len(s.exec(select(Alert).where(Alert.rule_id == D2_RULE_ID)).all()) == 1
