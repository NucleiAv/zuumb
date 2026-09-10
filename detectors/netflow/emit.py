"""D2 step 3: turn a `Beacon` finding into a Wazuh-shaped alert and hand it to
zuumb through the shared ingest path (`detectors.ingest`).

Same rules as D1's emit: the dict matches `normalize_alert`; `id` is a hash with
no wall-clock (`src|dst|port|date`) so a re-scan of the same day's beacon
dedupes; `rule.id` is 901001, in D2's reserved 901001-901999 band.

`host` — the vantage point the connections were seen from — is set as
`agent.name` when known, so a D2 beacon and a D1 auth anomaly on the *same host*
share an entity and correlate into one incident. `data.srcip` / `data.dstip`
are always set, so they also correlate on IP.
"""
from __future__ import annotations

import hashlib

from detectors.ingest import ingest_with_retry
from detectors.netflow.beacon import Beacon

D2_RULE_ID = "901001"  # reserved band 901001-901999 (plan Section 0.5 point 2)
D2_RULE_GROUPS = ["ml", "ids", "c2_beacon"]

__all__ = ["beacon_to_alert", "beacon_alerts", "ingest_with_retry", "D2_RULE_ID"]


def _alert_id(b: Beacon) -> str:
    key = f"{b.src_ip}|{b.dst_ip}|{b.dst_port}|{b.first_ts.date().isoformat()}"
    return "ml-d2-" + hashlib.sha256(key.encode()).hexdigest()[:16]  # dedup key, not crypto


def _rule_level(b: Beacon) -> int:
    """Wazuh-style 0-16. A tight, long, high-count beacon rates higher; still
    capped modest — this is 'look now', not 'confirmed C2'."""
    return min(13, 8 + int(b.score))


def beacon_to_alert(b: Beacon, *, host: str | None = None) -> dict:
    mins = round(b.mean_gap_seconds / 60, 1)
    return {
        "id": _alert_id(b),
        "timestamp": b.first_ts.isoformat(),
        "rule": {
            "id": D2_RULE_ID,
            "level": _rule_level(b),
            "description": (f"ML: periodic outbound beacon {b.src_ip} -> {b.dst_ip}:{b.dst_port} "
                            f"every ~{mins} min, {b.hits} calls, jitter {b.cv:.0%}"),
            "groups": D2_RULE_GROUPS,
        },
        "agent": {"name": host or b.src_ip},
        "data": {
            "srcip": b.src_ip,
            "dstip": b.dst_ip,
            "beacon": {
                "detector": "netflow-d2",
                "dst_port": b.dst_port,
                "hits": b.hits,
                "mean_gap_seconds": b.mean_gap_seconds,
                "cv": b.cv,
                "span_seconds": b.span_seconds,
                "score": b.score,
            },
        },
        "full_log": (f"netflow beacon detector: {b.src_ip} -> {b.dst_ip}:{b.dst_port}, "
                     f"{b.hits} connections over {b.span_seconds / 3600:.1f}h, "
                     f"mean gap {b.mean_gap_seconds}s, CV {b.cv}, score {b.score}"),
    }


def beacon_alerts(beacons, *, host: str | None = None) -> list[dict]:
    return [beacon_to_alert(b, host=host) for b in beacons]
