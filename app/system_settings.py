"""Deployment-wide toggles — one row, shared by every analyst, not a per-user
preference. Currently just the nav-bar AI detection switch: on, triage calls
the LLM as usual; off, triage falls back to the local second-opinion
classifier so alerts still get an automatic verdict without any LLM call."""
from __future__ import annotations

from datetime import datetime, timezone

from app.db.models import SystemSetting


def ai_triage_enabled(session) -> bool:
    row = session.get(SystemSetting, 1)
    return row.ai_triage_enabled if row else True


def set_ai_triage_enabled(session, value: bool) -> None:
    row = session.get(SystemSetting, 1) or SystemSetting(id=1)
    row.ai_triage_enabled = value
    row.updated_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
