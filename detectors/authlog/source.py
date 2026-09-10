"""D1 live source: raw auth-log lines pulled from the Wazuh alerts index.

Confirmed against the running stack: every sshd / `/var/log/auth.log` event that
matches a rule lands in `wazuh-alerts-*` with the raw syslog line in `full_log`
(~1150/day on the two lab agents). D1's parser needs nothing else, and this
reuses the exact indexer connection + index `app.ingestion` already polls — no
`logall_json`, no archives pipeline, no config change.
"""
from __future__ import annotations

from datetime import datetime

import httpx

from app.config import settings

_AUTH_TERM = {"term": {"location": "/var/log/auth.log"}}


def fetch_auth_lines(since: datetime | None, *, client: httpx.Client | None = None,
                     limit: int = 5000) -> list[str]:
    """The raw `full_log` line of every auth-log alert newer than `since`, oldest
    first. `since=None` returns the whole (capped) window. The syslog line
    carries its own timestamp, which is what D1's parser buckets on."""
    must: list[dict] = [_AUTH_TERM]
    if since is not None:
        must.append({"range": {"timestamp": {"gt": since.isoformat()}}})
    body = {
        "size": limit,
        "sort": [{"timestamp": "asc"}],
        "_source": ["timestamp", "full_log"],
        "query": {"bool": {"must": must}},
    }
    url = f"{settings.wazuh_api_url.rstrip('/')}/{settings.wazuh_alerts_index}/_search"
    own = client is None
    client = client or httpx.Client(
        verify=settings.wazuh_verify_ssl,
        auth=(settings.wazuh_api_user, settings.wazuh_api_password),
        timeout=30,
    )
    try:
        resp = client.post(url, json=body)
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
        return [h["_source"]["full_log"] for h in hits if h["_source"].get("full_log")]
    finally:
        if own:
            client.close()
