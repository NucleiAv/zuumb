"""One end-to-end pass: poll Wazuh -> triage new alerts -> correlate -> stitch.

Used by the live background poller (app.main lifespan). Response tasks are proposed
lazily when an incident is opened, so they're not part of the cycle.
"""
from __future__ import annotations

import logging

from sqlmodel import select

from app import deadletter
from app.attack_chain.stitcher import stitch
from app.config import settings
from app.correlation.engine import correlate
from app.db.models import Alert, Verdict
from app.db.session import get_session
from app.ingestion.wazuh_client import poll_once
from app.triage.agent import triage_alert

log = logging.getLogger("uvicorn.error")


def triage_pending(session, *, call=None, limit: int | None = None) -> int:
    """Triage alerts without a verdict, oldest first. `call=None` -> the real LLM.
    `limit` caps one call so the live poller does bounded work per tick.
    Returns the number successfully triaged.

    item 12: each alert is tried on its own, so a bad model response can't abort
    the rest of the cycle; after `triage_max_attempts` failures the alert is
    quarantined and skipped, so it can't be retried first forever.
    """
    done = set(session.exec(select(Verdict.alert_id)).all())
    spent = deadletter.attempts_for(session, "triage")
    pending = [a for a in session.exec(select(Alert).order_by(Alert.timestamp)).all()
               if a.id not in done and spent.get(str(a.id), 0) < settings.triage_max_attempts]
    ok = 0
    for alert in pending[:limit]:
        try:
            triage_alert(alert, session=session, call=call)
            ok += 1
        except Exception as e:
            deadletter.record(session, "triage", alert.id, e)
            log.warning("triage: alert %s failed, attempt logged: %s", alert.id, e)
    return ok


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
