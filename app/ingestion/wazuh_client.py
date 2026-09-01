"""Ingestion: Wazuh alert JSON -> normalized `Alert` rows.

- File replay (`ingest`) for synthetic sets.
- Live polling (`poll_once`) of the Wazuh indexer's `wazuh-alerts-*` via `_search`,
  with a timestamp cursor. Downstream stages are untouched — a live alert normalizes
  to the same `Alert` shape as a synthetic one.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import httpx
from sqlmodel import Session, func, select

from app.config import settings
from app.db.models import Alert
from app.db.session import get_session, init_db

# Wazuh nests the acting user under several keys depending on the decoder.
_USER_PATHS = (
    ("data", "srcuser"),
    ("data", "dstuser"),
    ("data", "user"),
    ("data", "win", "eventdata", "targetUserName"),
)


def _dig(d: dict, *keys: str):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _parse_ts(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw)  # 3.11+ handles "+0000"
    except ValueError:
        return datetime.strptime(raw[:19], "%Y-%m-%dT%H:%M:%S")


def normalize_alert(raw: dict) -> Alert:
    """Map one Wazuh alert dict to an `Alert`. Raises KeyError if it isn't one."""
    user = next((v for p in _USER_PATHS if (v := _dig(raw, *p))), None)
    return Alert(
        wazuh_alert_id=str(raw["id"]),
        timestamp=_parse_ts(raw["timestamp"]),
        rule_id=str(raw["rule"]["id"]),
        rule_description=raw["rule"]["description"],
        agent_name=_dig(raw, "agent", "name"),
        src_ip=_dig(raw, "data", "srcip"),
        dst_ip=_dig(raw, "data", "dstip"),
        user=user,
        raw_json=json.dumps(raw, separators=(",", ":")),
    )


def load_alerts(path: str | Path) -> list[dict]:
    """Load alert dicts from a .jsonl/.json file or a directory of them."""
    path = Path(path)
    files = sorted(path.glob("*.json*")) if path.is_dir() else [path]
    alerts: list[dict] = []
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if f.suffix == ".jsonl":
            alerts += [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            doc = json.loads(text)
            alerts += doc if isinstance(doc, list) else [doc]
    return alerts


def ingest_alerts(alerts: list[dict], session: Session | None = None) -> int:
    """Normalize + dedupe (on wazuh_alert_id, in-batch and vs DB) + store. New-row count."""
    init_db()
    own = session is None
    session = session or get_session()
    try:
        seen = set(session.exec(select(Alert.wazuh_alert_id)).all())
        new = []
        for raw in alerts:
            alert = normalize_alert(raw)
            if alert.wazuh_alert_id in seen:
                continue
            seen.add(alert.wazuh_alert_id)
            new.append(alert)
        session.add_all(new)
        session.commit()
        return len(new)
    finally:
        if own:
            session.close()


def ingest(path: str | Path, session: Session | None = None) -> int:
    """Replay alert files from `path` into the DB. Returns new-row count."""
    return ingest_alerts(load_alerts(path), session)


# --- live polling of the Wazuh indexer -----------------------------------------

def fetch_alerts_since(since: datetime | None, *,
                       client: httpx.Client | None = None) -> list[dict]:
    """`wazuh-alerts-*` `_source` docs with `timestamp` strictly after `since`, ascending."""
    query = {"range": {"timestamp": {"gt": since.isoformat()}}} if since else {"match_all": {}}
    body = {"size": 500, "sort": [{"timestamp": "asc"}], "query": query}
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
        return [hit["_source"] for hit in resp.json()["hits"]["hits"]]
    finally:
        if own:
            client.close()


def poll_once(session: Session | None = None, *, client: httpx.Client | None = None) -> int:
    """Fetch alerts newer than the newest one stored and ingest them. New-row count.

    ponytail: the cursor is just max(Alert.timestamp) — no state table. `ingest_alerts`
    dedupes on wazuh_alert_id, so a re-fetch of the boundary second is harmless.
    """
    init_db()
    own = session is None
    session = session or get_session()
    try:
        cursor = session.exec(select(func.max(Alert.timestamp))).one()
        raw = fetch_alerts_since(cursor, client=client)
        return ingest_alerts(raw, session)
    finally:
        if own:
            session.close()
