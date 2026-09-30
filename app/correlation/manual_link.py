"""Human-confirmed manual links between incidents.

A third, distinct layer alongside the deterministic entity/time correlation
in engine.py and the advisory embedding similarity in similarity.py:

  - engine.py:     shared host/IP/user within a time window -> automatic, drives incidents
  - similarity.py: local embedding model, no shared entity  -> advisory hint, drives nothing
  - this module:   an analyst clicked "confirm"              -> explicit record, drives nothing

Nothing here is read by correlate(), stitch(), or incident_severity() — see
tests/test_manual_link.py for the guard asserting that stays true. This is
a note a human wrote down, not a system-generated artifact of any kind.
"""
from __future__ import annotations

from sqlmodel import Session, or_, select

from app.db.models import Incident, ManualIncidentLink


def confirm(session: Session, incident_a_id: int, incident_b_id: int,
            linked_by: str, note: str = "") -> ManualIncidentLink:
    """Record a human-confirmed link. Confirming an already-confirmed pair
    (either order) returns the existing row unchanged rather than duplicating
    it — a double-click isn't a second judgment call. Stored with the lower
    id first, so the pair has one canonical row no matter which incident's
    page the analyst confirmed it from."""
    lo, hi = sorted((incident_a_id, incident_b_id))
    existing = session.exec(
        select(ManualIncidentLink).where(
            ManualIncidentLink.incident_a_id == lo, ManualIncidentLink.incident_b_id == hi
        )
    ).first()
    if existing:
        return existing
    row = ManualIncidentLink(incident_a_id=lo, incident_b_id=hi, linked_by=linked_by, note=note)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def unlink(session: Session, link_id: int) -> bool:
    """Remove a confirmed link. An analyst's past judgment call isn't permanent
    once written — they can correct it. Returns False if it's already gone."""
    row = session.get(ManualIncidentLink, link_id)
    if row is None:
        return False
    session.delete(row)
    session.commit()
    return True


def for_incident(session: Session, incident_id: int) -> list[dict]:
    """Confirmed links touching this incident, for the detail page:
    [{"link": ManualIncidentLink, "incident": Incident}], most recent first."""
    rows = session.exec(
        select(ManualIncidentLink).where(
            or_(ManualIncidentLink.incident_a_id == incident_id,
                ManualIncidentLink.incident_b_id == incident_id)
        )
    ).all()
    out = []
    for r in rows:
        other_id = r.incident_b_id if r.incident_a_id == incident_id else r.incident_a_id
        other = session.get(Incident, other_id)
        if other:
            out.append({"link": r, "incident": other})
    return sorted(out, key=lambda d: d["link"].linked_at, reverse=True)
