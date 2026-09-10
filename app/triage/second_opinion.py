"""D3: a lightweight, local, deterministic second-opinion verdict classifier.

Additive only. The Claude verdict from `triage/agent.py` stays the primary call;
this is a cheap cross-check trained on `eval/labeled_set.jsonl` (34 synthetic,
self-labeled alerts). When the two disagree it's a nudge for a human to look at
that alert — nothing more. It drives no severity, no correlation, no response.

No transformer, no GPU, no new dependency: TF-IDF + logistic regression over the
same alert-brief text the LLM sees. Because the training set is 34 examples this
is a rough signal by construction; treat the numbers as directional.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sqlmodel import Session, select

from app.db.models import Alert, Verdict
from app.db.session import get_session, init_db
from app.redact import redact
from app.triage.agent import _alert_brief

LABELS = ("benign", "suspicious", "malicious")
_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
_LABELED = Path(__file__).parents[2] / "eval" / "labeled_set.jsonl"


def escalates(primary: str, second: str | None) -> bool:
    """True only when the second opinion is *stricter* than the primary verdict.
    That's the one direction worth an analyst's attention (a possible missed
    detection); a more-lenient second opinion is just noise and isn't surfaced."""
    return bool(second) and _RANK.get(second, 0) > _RANK.get(primary, 0)


@lru_cache(maxsize=1)
def _model() -> Pipeline:
    """Fit once per process on the labeled eval set. ~30 rows, sub-second."""
    from app.ingestion.wazuh_client import normalize_alert  # lazy: avoid import cycle

    rows = [json.loads(ln) for ln in _LABELED.read_text(encoding="utf-8").splitlines() if ln.strip()]
    X = [redact(_alert_brief(normalize_alert(r["alert"]))) for r in rows]
    y = [r["label"] for r in rows]
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(C=4.0, class_weight="balanced", max_iter=1000)),
    ])
    pipe.fit(X, y)
    return pipe


def second_opinion(brief: str) -> tuple[str, float]:
    """(label, confidence 0..1) for an alert brief. Deterministic."""
    m = _model()
    proba = m.predict_proba([redact(brief)])[0]
    i = proba.argmax()
    return str(m.classes_[i]), round(float(proba[i]), 3)


def backfill(session: Session | None = None) -> int:
    """Fill second_opinion on verdicts that don't have one yet. Returns the count."""
    init_db()  # ensure the second_opinion columns exist on an older DB file
    own = session is None
    session = session or get_session()
    try:
        pending = session.exec(select(Verdict).where(Verdict.second_opinion.is_(None))).all()
        alerts = {a.id: a for a in session.exec(select(Alert)).all()}
        n = 0
        for v in pending:
            a = alerts.get(v.alert_id)
            if a is None:
                continue
            v.second_opinion, v.second_opinion_confidence = second_opinion(_alert_brief(a))
            n += 1
        session.commit()
        return n
    finally:
        if own:
            session.close()


if __name__ == "__main__":  # python -m app.triage.second_opinion
    print(f"backfilled second opinion on {backfill()} verdict(s)")
