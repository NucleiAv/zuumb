"""Quarantine for records that won't process (item 12).

`record()` upserts a `DeadLetter` row per (source, key) and bumps `attempts`.
`attempts_for()` lets a caller skip a record that has failed too many times, so
one poison alert or bad model response can't block the rest of the pipeline.
"""
from __future__ import annotations

from sqlmodel import Session, func, select

from app.db.models import DeadLetter

_ERR_MAX = 500


def record(session: Session, source: str, key, error) -> DeadLetter:
    row = session.exec(
        select(DeadLetter).where(DeadLetter.source == source, DeadLetter.key == str(key))
    ).first()
    if row is None:
        row = DeadLetter(source=source, key=str(key), error=str(error)[:_ERR_MAX])
    else:
        row.attempts += 1
        row.error = str(error)[:_ERR_MAX]
    session.add(row)
    session.commit()
    return row


def attempts_for(session: Session, source: str) -> dict[str, int]:
    """key -> attempts, for the given source."""
    return {r.key: r.attempts
            for r in session.exec(select(DeadLetter).where(DeadLetter.source == source)).all()}


def count(session: Session) -> int:
    return session.exec(select(func.count()).select_from(DeadLetter)).one()
