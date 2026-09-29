"""Advisory-only semantic similarity between incidents, on top of the
deterministic entity/time correlation in engine.py — never a replacement for
it. Two incidents can share no host, IP, or user and still be the same
campaign; entity correlation and the chain stitcher can't see that, but a
sentence embedding on what the alerts actually say can. Flagged for a human
to glance at, same trust posture as D3's second opinion (app/triage/
second_opinion.py): surfaced, never authoritative, and it never merges,
reorders, or overrides anything the deterministic engine already decided.

Runs entirely locally (fastembed + ONNX, no GPU, no API call, no network
after the model's one-time download) over the same medium/high-severity
incident population the chain stitcher already considers.
"""
from __future__ import annotations

from functools import lru_cache

import numpy as np
from sqlmodel import Session, delete, select

from app.config import settings
from app.correlation.engine import entities, signal_alerts
from app.db.models import Alert, Incident, IncidentAlert, IncidentSimilarity, Verdict
from app.redact import redact

_MIN_CANDIDATES = 2  # nothing to compare below this


@lru_cache(maxsize=1)
def _model():
    from fastembed import TextEmbedding
    return TextEmbedding(model_name=settings.similarity_model, cache_dir=settings.model_dir)


def _incident_brief(alerts: list[Alert]) -> str:
    """What happened, not who or where — host/IP/user are deliberately left
    out so similarity reflects the pattern of activity, not incidental entity
    string overlap (two incidents that share an entity are already the
    deterministic engine's job; this module is for the ones that don't)."""
    return redact(" ".join(sorted({a.rule_description for a in alerts})))


def find_similar(session: Session) -> list[tuple[int, int, float]]:
    """(incident_a_id, incident_b_id, score) for every medium/high incident
    pair at or above settings.similarity_threshold that shares no entity.
    Pure computation past the initial reads — no DB writes."""
    verdict = {v.alert_id: v.verdict for v in session.exec(select(Verdict)).all()}
    incidents = [i for i in session.exec(select(Incident)).all() if i.severity in ("medium", "high")]
    if len(incidents) < _MIN_CANDIDATES:
        return []

    alerts_by_incident: dict[int, list[Alert]] = {}
    for i in incidents:
        alert_ids = [link.alert_id for link in session.exec(
            select(IncidentAlert).where(IncidentAlert.incident_id == i.id)).all()]
        alerts_by_incident[i.id] = session.exec(select(Alert).where(Alert.id.in_(alert_ids))).all()

    ent = {
        i.id: set().union(*(entities(a) for a in signal_alerts(alerts_by_incident[i.id], verdict)), set())
        for i in incidents
    }
    briefs = [_incident_brief(alerts_by_incident[i.id]) for i in incidents]

    vectors = np.array(list(_model().embed(briefs)))
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    unit = vectors / np.where(norms == 0, 1, norms)  # guard: an empty brief embeds to all-zero
    sims = unit @ unit.T

    out = []
    for a_idx in range(len(incidents)):
        for b_idx in range(a_idx + 1, len(incidents)):
            a, b = incidents[a_idx], incidents[b_idx]
            if ent[a.id] & ent[b.id]:
                continue  # already the deterministic engine's or the chain stitcher's job
            score = float(sims[a_idx, b_idx])
            if score >= settings.similarity_threshold:
                out.append((a.id, b.id, round(score, 3)))
    return out


def refresh(session: Session | None = None) -> list[IncidentSimilarity]:
    """Rebuild IncidentSimilarity from scratch — the same idempotent
    delete-and-recreate pattern stitch() uses for AttackChain."""
    from app.db.session import get_session, init_db
    init_db()
    own = session is None
    session = session or get_session()
    try:
        pairs = find_similar(session)
        session.exec(delete(IncidentSimilarity))
        rows = [IncidentSimilarity(incident_a_id=a, incident_b_id=b, score=s) for a, b, s in pairs]
        session.add_all(rows)
        session.commit()
        for r in rows:
            session.refresh(r)
        return rows
    finally:
        if own:
            session.close()


def for_incident(session: Session, incident_id: int) -> list[dict]:
    """Similar incidents for the detail page: [{"incident": Incident, "score": float}],
    highest score first."""
    rows = session.exec(
        select(IncidentSimilarity).where(
            (IncidentSimilarity.incident_a_id == incident_id)
            | (IncidentSimilarity.incident_b_id == incident_id)
        )
    ).all()
    out = []
    for r in rows:
        other_id = r.incident_b_id if r.incident_a_id == incident_id else r.incident_a_id
        other = session.get(Incident, other_id)
        if other:
            out.append({"incident": other, "score": r.score})
    return sorted(out, key=lambda d: -d["score"])
