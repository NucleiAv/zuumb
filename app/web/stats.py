"""Dashboard aggregates for the incidents page charts. Pure read, no new tables.

Timestamps stored naive-UTC; time-bucketed views (heatmap, timeline) are built
client-side in the viewer's local zone from the raw `events` feed, so this module
never buckets or formats by hour/weekday.
"""
from collections import Counter
from datetime import timezone

from sqlmodel import Session, func, select

from app.config import settings
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
    alert_incident = {x.alert_id: x.incident_id for x in links}
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
        # global (not window-scoped): how far the triage backlog has drained
        "triage": {
            "done": session.exec(select(func.count(func.distinct(Verdict.alert_id)))).one(),
            "total": session.exec(select(func.count()).select_from(Alert)).one(),
        },
        "window_minutes": settings.correlation_window_minutes,
        "severity": {k: severity.get(k, 0) for k in ("low", "medium", "high")},
        "verdict_dist": {k: vdist.get(k, 0) for k in ("benign", "suspicious", "malicious")},
        "by_src_ip": _top(alerts, verdict, lambda a: a.src_ip),
        "by_host": _top(alerts, verdict, lambda a: a.agent_name),
        "by_rule": _top(alerts, verdict, lambda a: f"{a.rule_id} {a.rule_description}"),
        "by_mitre": _top_pairs((v.mitre_technique, _RANK.get(v.verdict, 0)) for v in verdict_rows),
        # raw feed: [epoch_ms, incident_id or 0] per alert. The heatmap and timeline
        # are bucketed from this in charts.js, in the viewer's local zone.
        "events": sorted(
            [int(a.timestamp.replace(tzinfo=timezone.utc).timestamp() * 1000),
             alert_incident.get(a.id, 0)]
            for a in alerts
        ),
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


