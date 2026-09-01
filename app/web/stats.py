"""Dashboard aggregates for the incidents page charts. Pure read, no new tables."""
from collections import Counter
from datetime import timedelta

from sqlmodel import Session, select

from app.db.models import Alert, Incident, IncidentAlert, Verdict

TOP_N = 10
_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
_SEV_NAME = {0: "low", 1: "medium", 2: "high"}  # worst verdict rank -> severity bucket
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def compute_stats(session: Session, since=None, until=None) -> dict:
    """All aggregates. `since`/`until` (datetimes) restrict to alerts in that window."""
    aq = select(Alert)
    if since is not None:
        aq = aq.where(Alert.timestamp >= since)
    if until is not None:
        aq = aq.where(Alert.timestamp <= until)
    alerts = session.exec(aq).all()
    alert_ids = {a.id for a in alerts}

    links = [x for x in session.exec(select(IncidentAlert)).all() if x.alert_id in alert_ids]
    inc_ids = {x.incident_id for x in links}
    incidents = [i for i in session.exec(select(Incident)).all() if i.id in inc_ids]
    verdict_rows = [v for v in session.exec(select(Verdict)).all() if v.alert_id in alert_ids]
    verdict = {v.alert_id: v.verdict for v in verdict_rows}

    hosts = {a.agent_name for a in alerts if a.agent_name and a.id in {x.alert_id for x in links}}
    severity = Counter(i.severity for i in incidents)
    vdist = Counter(v.verdict for v in verdict_rows)

    return {
        "kpis": {
            "alerts": len(alerts),
            "incidents": len(incidents),
            "high_incidents": severity.get("high", 0),
            "hosts": len(hosts),
        },
        "severity": {k: severity.get(k, 0) for k in ("low", "medium", "high")},
        "verdict_dist": {k: vdist.get(k, 0) for k in ("benign", "suspicious", "malicious")},
        "by_src_ip": _top(alerts, verdict, lambda a: a.src_ip),
        "by_host": _top(alerts, verdict, lambda a: a.agent_name),
        "by_rule": _top(alerts, verdict, lambda a: f"{a.rule_id} {a.rule_description}"),
        "by_mitre": _top_pairs((v.mitre_technique, _RANK.get(v.verdict, 0)) for v in verdict_rows),
        "timeline": _timeline(alerts, links),
        "heatmap": _heatmap(alerts),
    }


def _top(alerts, verdict, key) -> list[list]:
    """Top-N buckets as [label, count, severity]; severity = worst verdict in the bucket."""
    return _top_pairs((key(a), _RANK.get(verdict.get(a.id), 0)) for a in alerts)


def _top_pairs(label_rank_pairs) -> list[list]:
    buckets: dict[str, list] = {}
    for label, rank in label_rank_pairs:
        if not label:
            continue
        b = buckets.setdefault(label, [0, 0])
        b[0] += 1
        b[1] = max(b[1], rank)
    top = sorted(buckets.items(), key=lambda kv: kv[1][0], reverse=True)[:TOP_N]
    return [[label, cnt, _SEV_NAME[rank]] for label, (cnt, rank) in top]


def _heatmap(alerts: list[Alert]) -> dict:
    """Alert volume by weekday (row) x hour-of-day (col)."""
    matrix = [[0] * 24 for _ in range(7)]
    for a in alerts:
        matrix[a.timestamp.weekday()][a.timestamp.hour] += 1
    peak = max((c for row in matrix for c in row), default=0)
    return {"days": DAYS, "matrix": matrix, "max": peak}


def _floor_hour(ts):
    return ts.replace(minute=0, second=0, microsecond=0)


def _timeline(alerts: list[Alert], links: list[IncidentAlert]) -> dict:
    if not alerts:
        return {"labels": [], "alerts": [], "incidents": []}

    alert_incident = {link.alert_id: link.incident_id for link in links}  # correlate: 1 incident/alert
    start, end = _floor_hour(min(a.timestamp for a in alerts)), _floor_hour(max(a.timestamp for a in alerts))
    buckets = []
    t = start
    while t <= end:
        buckets.append(t)
        t += timedelta(hours=1)
    pos = {b: i for i, b in enumerate(buckets)}

    alert_counts = [0] * len(buckets)
    incident_sets: list[set] = [set() for _ in buckets]
    for a in alerts:
        i = pos[_floor_hour(a.timestamp)]
        alert_counts[i] += 1
        inc = alert_incident.get(a.id)
        if inc is not None:
            incident_sets[i].add(inc)

    return {
        "labels": [b.strftime("%m-%d %H:%M") for b in buckets],
        "alerts": alert_counts,
        "incidents": [len(s) for s in incident_sets],
    }
