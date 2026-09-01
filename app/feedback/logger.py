"""Feedback loop: record analyst verdict overrides, feed the last K back into triage.

The triage agent imports `few_shot_block` and appends it to the system prompt so
recent corrections become in-context examples (plan step 9 — no fine-tuning).
"""
from __future__ import annotations

from sqlmodel import Session, select

from app.db.models import Alert, AnalystFeedback, Verdict

VERDICTS = {"benign", "suspicious", "malicious"}


def record_override(session: Session, verdict_id: int, analyst_verdict: str, note: str = "") -> AnalystFeedback:
    if analyst_verdict not in VERDICTS:
        raise ValueError(f"analyst_verdict must be one of {sorted(VERDICTS)}")
    if session.get(Verdict, verdict_id) is None:
        raise ValueError(f"verdict {verdict_id} not found")
    fb = AnalystFeedback(verdict_id=verdict_id, analyst_verdict=analyst_verdict, note=note.strip())
    session.add(fb)
    session.commit()
    session.refresh(fb)
    return fb


def recent_overrides(session: Session, k: int = 5) -> list[tuple[AnalystFeedback, Verdict, Alert]]:
    """The last K corrections, newest first, each with its model verdict + alert."""
    return session.exec(
        select(AnalystFeedback, Verdict, Alert)
        .join(Verdict, AnalystFeedback.verdict_id == Verdict.id)
        .join(Alert, Verdict.alert_id == Alert.id)
        .order_by(AnalystFeedback.created_at.desc(), AnalystFeedback.id.desc())
        .limit(k)
    ).all()


def few_shot_block(session: Session, k: int = 5) -> str:
    """Text to append to the triage system prompt. '' when there are no overrides."""
    rows = recent_overrides(session, k)
    if not rows:
        return ""
    lines = ["\n## Recent analyst corrections (weigh these when the alert resembles one)"]
    for fb, v, a in reversed(rows):  # oldest first reads better as examples
        note = f" Note: {fb.note}" if fb.note else ""
        lines.append(
            f'- rule {a.rule_id} "{a.rule_description}" on {a.agent_name or "?"} '
            f"(src {a.src_ip or '-'}, user {a.user or '-'}): "
            f"model said {v.verdict}, analyst corrected to {fb.analyst_verdict}.{note}"
        )
    return "\n".join(lines) + "\n"
