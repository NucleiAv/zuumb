"""Shared hand-off from any detector to zuumb.

Every detector in this track emits alerts in the `normalize_alert` shape and
pushes them through the same ingest path Wazuh alerts use (plan Section 0.5
point 3), so they get the exact same dedupe/idempotency guarantees.
"""
from __future__ import annotations

import time

from sqlalchemy.exc import OperationalError

from app.ingestion.wazuh_client import ingest_alerts


def ingest_with_retry(alerts: list[dict], *, attempts: int = 5, backoff: float = 0.5) -> int:
    """`ingest_alerts`, retrying past the SQLite single-writer lock. Returns the
    new-row count (0 when every alert was already present)."""
    for i in range(attempts):
        try:
            return ingest_alerts(alerts)
        except OperationalError as e:
            if "database is locked" not in str(e).lower() or i == attempts - 1:
                raise
            time.sleep(backoff * (i + 1))
    return 0  # unreachable
