"""Ingestion: Wazuh alert JSON -> normalized `Alert` rows.

POC scope: read synthetic alert files, normalize, write to DB.
Live Wazuh API polling is deferred to the MVP (plan: "real-time-ish polling").
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from sqlmodel import Session, select

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


def ingest(path: str | Path, session: Session | None = None) -> int:
    """Normalize alerts from `path` into the DB, skipping ones already stored.

    Returns the number of new rows written.
    """
    init_db()
    own = session is None
    session = session or get_session()
    try:
        seen = set(session.exec(select(Alert.wazuh_alert_id)).all())
        new = []
        for raw in load_alerts(path):
            alert = normalize_alert(raw)
            if alert.wazuh_alert_id in seen:
                continue
            seen.add(alert.wazuh_alert_id)  # also dedupes within this batch
            new.append(alert)
        session.add_all(new)
        session.commit()
        return len(new)
    finally:
        if own:
            session.close()
