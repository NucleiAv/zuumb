"""D1 step 4: turn a flagged window into a Wazuh-shaped alert and hand it to
zuumb through the same ingest path Wazuh alerts use.

The dict matches what `app.ingestion.wazuh_client.normalize_alert` expects
(plan Section 0.5 point 1). `id` is minted per point 1a — a hash of host +
template set + window bounds, no wall-clock — so a re-run of the detector over
the same window produces the same id and `ingest_alerts`' dedupe absorbs it.
`rule.id` sits in D1's reserved 900001-900999 band (point 2).
"""
from __future__ import annotations

import hashlib
from datetime import timedelta

from detectors.authlog.features import DEFAULT_WINDOW_SECONDS
from detectors.authlog.model import DEFAULT_Z, ScoredWindow
from detectors.ingest import ingest_with_retry  # re-exported; shared by every detector

__all__ = ["window_to_alert", "flagged_alerts", "ingest_with_retry", "D1_RULE_ID"]

D1_RULE_ID = "900001"  # reserved band 900001-900999 (plan Section 0.5 point 2)
D1_RULE_GROUPS = ["ml", "ids", "authentication_anomaly"]


def _alert_id(sw: ScoredWindow, window_seconds: int) -> str:
    end = sw.row.window_start + timedelta(seconds=window_seconds)
    tset = ",".join(str(t) for t in sorted(sw.row.template_counts))
    key = f"{sw.row.host}|{tset}|{sw.row.window_start.isoformat()}|{end.isoformat()}"
    return "ml-d1-" + hashlib.sha256(key.encode()).hexdigest()[:16]  # dedup key, not crypto


def _rule_level(z: float, z_threshold: float) -> int:
    """Wazuh-style 0-16 level, scaled from how far past the flag threshold the
    window landed. Kept modest: this means 'a human should look', not 'confirmed'."""
    return min(13, 9 + max(0, int(z - z_threshold)))


def window_to_alert(sw: ScoredWindow, *, window_seconds: int = DEFAULT_WINDOW_SECONDS,
                    z_threshold: float = DEFAULT_Z) -> dict:
    r = sw.row
    win_min = round(window_seconds / 60)
    start_iso = r.window_start.isoformat()
    end_iso = (r.window_start + timedelta(seconds=window_seconds)).isoformat()
    return {
        "id": _alert_id(sw, window_seconds),
        "timestamp": start_iso,
        "rule": {
            "id": D1_RULE_ID,
            "level": _rule_level(sw.z, z_threshold),
            "description": (f"ML: unusual auth-log activity on {r.host} - "
                            f"{r.n_events} events in a {win_min} min window (anomaly z={sw.z:.1f})"),
            "groups": D1_RULE_GROUPS,
        },
        "agent": {"name": r.host},
        "full_log": (f"authlog anomaly detector: {r.host} window {start_iso}..{end_iso}, "
                     f"{r.n_events} events across {r.n_distinct_templates} templates, "
                     f"rate {r.events_per_min}/min, score z={sw.z:.2f}"),
        # data.* is surfaced (curated) on the alert-detail view; no srcip/user here
        # because template mining masked them out, so this alert is host-scoped only.
        "data": {"ml_anomaly": {
            "detector": "authlog-d1",
            "score": round(sw.score, 4),
            "z": round(sw.z, 3),
            "n_events": r.n_events,
            "window_minutes": win_min,
            "template_counts": {str(k): v for k, v in r.template_counts.items()},
        }},
    }


def flagged_alerts(scored, *, window_seconds: int = DEFAULT_WINDOW_SECONDS,
                   z_threshold: float = DEFAULT_Z) -> list[dict]:
    return [window_to_alert(sw, window_seconds=window_seconds, z_threshold=z_threshold)
            for sw in scored if sw.is_anomaly]
