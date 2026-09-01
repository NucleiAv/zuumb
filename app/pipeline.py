"""One end-to-end pass: poll Wazuh -> triage new alerts -> correlate -> stitch.

Used by the live background poller (app.main lifespan). Response tasks are proposed
lazily when an incident is opened, so they're not part of the cycle.
"""
from __future__ import annotations

from sqlmodel import select

from app.attack_chain.stitcher import stitch
from app.correlation.engine import correlate
from app.db.models import Alert, Verdict
from app.db.session import get_session
from app.ingestion.wazuh_client import poll_once
from app.triage.agent import triage_alert


def triage_pending(session, *, call=None, limit: int | None = None) -> int:
    """Triage alerts without a verdict, oldest first. `call=None` -> the real LLM.
    `limit` caps one call so the live poller does bounded work per tick."""
    done = set(session.exec(select(Verdict.alert_id)).all())
    pending = [a for a in session.exec(select(Alert).order_by(Alert.timestamp)).all()
               if a.id not in done]
    for alert in pending[:limit]:
        triage_alert(alert, session=session, call=call)
    return min(len(pending), limit) if limit else len(pending)


# The live poller triages at most this many alerts per tick, so a large first
# backlog drains over several cycles instead of blocking correlate() for minutes.
_TRIAGE_PER_CYCLE = 40


def run_pipeline_cycle(*, call=None, client=None) -> dict:
    with get_session() as s:
        ingested = poll_once(s, client=client)
        triaged = triage_pending(s, call=call, limit=_TRIAGE_PER_CYCLE)
        if ingested or triaged:  # nothing new -> skip the derived-state rebuild
            correlate(session=s)
            stitch(session=s)
    return {"ingested": ingested, "triaged": triaged}
