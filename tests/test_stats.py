from datetime import datetime

from sqlmodel import select

from app.db.models import Alert, Incident, IncidentAlert, Verdict
from app.db.session import get_session
from app.web.stats import compute_stats


def _seed():
    with get_session() as s:
        alerts = [
            Alert(wazuh_alert_id="a1", timestamp=datetime(2026, 8, 28, 14, 3), rule_id="31103",
                  rule_description="SQL injection attempt.", agent_name="web-01",
                  src_ip="203.0.113.44", raw_json="{}"),
            Alert(wazuh_alert_id="a2", timestamp=datetime(2026, 8, 28, 14, 40), rule_id="31103",
                  rule_description="SQL injection attempt.", agent_name="web-01",
                  src_ip="203.0.113.44", raw_json="{}"),
            Alert(wazuh_alert_id="a3", timestamp=datetime(2026, 8, 28, 15, 5), rule_id="5715",
                  rule_description="sshd: authentication success.", agent_name="db-01",
                  src_ip="198.51.100.9", raw_json="{}"),
        ]
        s.add_all(alerts)
        s.commit()
        for a in alerts:
            s.refresh(a)
        inc_hi = Incident(title="web-01", severity="high")
        inc_md = Incident(title="db-01", severity="medium")
        s.add_all([inc_hi, inc_md])
        s.commit()
        s.refresh(inc_hi)
        s.refresh(inc_md)
        s.add_all([
            IncidentAlert(incident_id=inc_hi.id, alert_id=alerts[0].id),
            IncidentAlert(incident_id=inc_hi.id, alert_id=alerts[1].id),
            IncidentAlert(incident_id=inc_md.id, alert_id=alerts[2].id),
        ])
        s.commit()


def test_compute_stats_shapes_and_counts():
    _seed()
    with get_session() as s:
        st = compute_stats(s)

    assert st["kpis"] == {"alerts": 3, "incidents": 2, "high_incidents": 1, "hosts": 2}
    assert st["severity"] == {"low": 0, "medium": 1, "high": 1}
    assert st["verdict_dist"] == {"benign": 0, "suspicious": 0, "malicious": 0}  # no verdicts seeded
    # [label, count, severity]; no verdicts seeded -> severity "low"
    assert ["203.0.113.44", 2, "low"] in st["by_src_ip"]
    assert ["web-01", 2, "low"] in st["by_host"]
    assert ["31103 SQL injection attempt.", 2, "low"] in st["by_rule"]


def test_top_bucket_severity_is_worst_verdict():
    _seed()
    with get_session() as s:
        a = s.exec(select(Alert).where(Alert.wazuh_alert_id == "a1")).one()
        s.add(Verdict(alert_id=a.id, verdict="malicious", confidence=0.9,
                      reasoning_text="x", model_version="t"))
        s.commit()
        st = compute_stats(s)
    host = dict((r[0], r[2]) for r in st["by_host"])
    assert host["web-01"] == "high"   # a1 is on web-01 and is now malicious
    assert host["db-01"] == "low"


def test_verdict_dist_counts_alert_verdicts_and_window_narrows():
    _seed()
    with get_session() as s:
        a1, a2, a3 = s.exec(select(Alert).order_by(Alert.wazuh_alert_id)).all()
        s.add_all([
            Verdict(alert_id=a1.id, verdict="malicious", confidence=0.9, reasoning_text="x", model_version="t"),
            Verdict(alert_id=a2.id, verdict="suspicious", confidence=0.5, reasoning_text="x", model_version="t"),
            Verdict(alert_id=a3.id, verdict="benign", confidence=0.6, reasoning_text="x", model_version="t"),
        ])
        s.commit()
        full = compute_stats(s)
        # a1/a2 at 14:xx, a3 at 15:xx — window to 15:00+ keeps only the benign one
        windowed = compute_stats(s, since=datetime(2026, 8, 28, 15, 0))
    assert full["verdict_dist"] == {"benign": 1, "suspicious": 1, "malicious": 1}
    assert windowed["verdict_dist"] == {"benign": 1, "suspicious": 0, "malicious": 0}
    assert windowed["kpis"]["alerts"] == 1


def test_by_mitre_groups_verdicts_by_technique():
    _seed()
    with get_session() as s:
        a1, a2, a3 = s.exec(select(Alert).order_by(Alert.wazuh_alert_id)).all()
        s.add_all([
            Verdict(alert_id=a1.id, verdict="malicious", confidence=0.9,
                    reasoning_text="x", model_version="t", mitre_technique="T1190"),
            Verdict(alert_id=a2.id, verdict="suspicious", confidence=0.5,
                    reasoning_text="x", model_version="t", mitre_technique="T1190"),
            Verdict(alert_id=a3.id, verdict="benign", confidence=0.6,
                    reasoning_text="x", model_version="t", mitre_technique=None),
        ])
        s.commit()
        st = compute_stats(s)
    assert st["by_mitre"] == [["T1190", 2, "high"]]  # None technique dropped; worst = malicious


def test_timeline_buckets_hourly_and_counts_incidents():
    _seed()
    with get_session() as s:
        tl = compute_stats(s)["timeline"]

    # 14:00 and 15:00 buckets span the seeded alerts
    assert tl["labels"] == ["08-28 14:00", "08-28 15:00"]
    assert tl["alerts"] == [2, 1]
    assert tl["incidents"] == [1, 1]  # inc_hi active in 14:00, inc_md in 15:00


def test_empty_db_stats_are_safe():
    with get_session() as s:
        st = compute_stats(s)
    assert st["kpis"] == {"alerts": 0, "incidents": 0, "high_incidents": 0, "hosts": 0}
    assert st["timeline"] == {"labels": [], "alerts": [], "incidents": []}
    assert st["by_host"] == []
    assert st["heatmap"]["max"] == 0
    assert len(st["heatmap"]["matrix"]) == 7 and len(st["heatmap"]["matrix"][0]) == 24


def test_heatmap_bins_alerts_by_weekday_and_hour():
    _seed()  # a1/a2 at 2026-08-28 14:xx, a3 at 15:xx
    dow = datetime(2026, 8, 28).weekday()
    with get_session() as s:
        hm = compute_stats(s)["heatmap"]
    assert hm["matrix"][dow][14] == 2
    assert hm["matrix"][dow][15] == 1
    assert hm["max"] == 2
