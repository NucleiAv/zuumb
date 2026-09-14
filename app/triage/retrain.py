"""D4: retrain the second-opinion classifier on real analyst feedback, gated so
a retrain can never quietly make production worse.

  label source    AnalystFeedback joined back to its alert, i.e. an analyst's
                   corrected verdict on an alert some detector already flagged.
                   This is triage-judgement ground truth, not a raw "was this
                   telemetry an intrusion" label — see second_opinion.py's
                   module docstring for the same distinction the D4 plan makes.
  held-out set    a stable, stratified 80/20 split of eval/labeled_set.jsonl,
                   fixed across every retrain (same seed) so accuracy is
                   comparable run to run even as feedback grows.
  promotion       a candidate replaces the current model only if its held-out
                   accuracy is >= the incumbent's ("never regress"). The very
                   first run always promotes — otherwise the registry, and the
                   dashboard, would stay silently empty forever.
  drift           cosine similarity between the TF-IDF centroid of a sample of
                   recently triaged alerts and the centroid of what the
                   promoted model trained on. Informational only — nothing
                   autonomous acts on a low score, it's a number to glance at.

Runs as its own process (`--live`), same as D1's detector: retraining is real
CPU work and must never be able to slow the dashboard.
"""
from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split
from sqlmodel import Session, select

from app.config import settings
from app.db.models import AnalystFeedback, Alert, ModelVersion, Verdict
from app.db.session import get_session, init_db
from app.redact import redact
from app.triage.agent import _alert_brief
from app.triage.second_opinion import eval_examples, get_promoted, new_pipeline

_DRIFT_SAMPLE = 200      # recent alerts to compare against the training centroid
_MIN_FOR_DRIFT = 20      # below this there isn't enough recent traffic to say anything
_SPLIT_SEED = 42         # fixed: the held-out set must be the same rows every run

log = logging.getLogger("uvicorn.error")


def _eval_split() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Stable 80/20 stratified split of the eval set: (train, held_out)."""
    examples = eval_examples()
    X, y = [e[0] for e in examples], [e[1] for e in examples]
    X_tr, X_ho, y_tr, y_ho = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=_SPLIT_SEED)
    return list(zip(X_tr, y_tr)), list(zip(X_ho, y_ho))


def feedback_examples(session: Session) -> list[tuple[str, str]]:
    """(brief, analyst-corrected label) for every recorded override, oldest first."""
    rows = session.exec(
        select(AnalystFeedback, Verdict, Alert)
        .join(Verdict, AnalystFeedback.verdict_id == Verdict.id)
        .join(Alert, Verdict.alert_id == Alert.id)
        .order_by(AnalystFeedback.created_at)
    ).all()
    return [(redact(_alert_brief(a)), fb.analyst_verdict) for fb, _v, a in rows]


def train_candidate(session: Session) -> tuple[object, float, int, list[str]]:
    """(pipeline, held_out_accuracy, n_feedback_used, training_texts)."""
    train, held_out = _eval_split()
    feedback = feedback_examples(session)
    examples = train + feedback
    X_train, y_train = [e[0] for e in examples], [e[1] for e in examples]

    pipe = new_pipeline()
    pipe.fit(X_train, y_train)

    X_ho, y_ho = [e[0] for e in held_out], [e[1] for e in held_out]
    accuracy = float(pipe.score(X_ho, y_ho))
    return pipe, round(accuracy, 3), len(feedback), X_train


def drift_score(pipe, training_texts: list[str], session: Session,
                sample: int = _DRIFT_SAMPLE) -> float | None:
    """Cosine similarity of the recent-alert centroid to the training centroid,
    in the candidate's own TF-IDF space. 1.0 = identical distribution, lower =
    more drift. None when there isn't enough recent traffic to judge."""
    recent = session.exec(select(Alert).order_by(Alert.timestamp.desc()).limit(sample)).all()
    if len(recent) < _MIN_FOR_DRIFT:
        return None
    vec = pipe.named_steps["tfidf"]
    recent_texts = [redact(_alert_brief(a)) for a in recent]
    train_centroid = np.asarray(vec.transform(training_texts).mean(axis=0)).ravel()
    recent_centroid = np.asarray(vec.transform(recent_texts).mean(axis=0)).ravel()
    denom = np.linalg.norm(train_centroid) * np.linalg.norm(recent_centroid)
    return round(float(train_centroid @ recent_centroid / denom), 3) if denom else None


def promote_if_better(session: Session, pipe, accuracy: float, n_feedback: int,
                      drift: float | None) -> ModelVersion:
    """Register this training run; promote it only if it beats (or there is no)
    incumbent. Demotes the previous promoted row when a new one takes over."""
    import joblib

    current = get_promoted(session)
    promote = current is None or accuracy >= current.held_out_accuracy

    row = ModelVersion(kind="second_opinion", n_feedback_examples=n_feedback,
                       held_out_accuracy=accuracy, drift_score=drift, promoted=promote)
    session.add(row)
    session.flush()  # assigns row.id without committing, so path can be set before the one commit

    if promote:
        model_dir = Path(settings.model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        row.path = f"second_opinion_v{row.id}.joblib"
        joblib.dump(pipe, model_dir / row.path)
        if current is not None:
            current.promoted = False
            session.add(current)

    session.commit()
    session.refresh(row)
    return row


def run_once(session: Session | None = None) -> dict:
    init_db()
    own = session is None
    session = session or get_session()
    try:
        pipe, accuracy, n_feedback, train_texts = train_candidate(session)
        drift = drift_score(pipe, train_texts, session)
        row = promote_if_better(session, pipe, accuracy, n_feedback, drift)
        return {"model_version_id": row.id, "held_out_accuracy": row.held_out_accuracy,
                "n_feedback_examples": row.n_feedback_examples, "drift_score": row.drift_score,
                "promoted": row.promoted}
    finally:
        if own:
            session.close()


def _live_loop(interval: int) -> None:
    log.info("second-opinion retrain: live, every %ss", interval)
    while True:
        try:
            r = run_once()
            log.info("second-opinion retrain: v%s acc=%s feedback=%s drift=%s promoted=%s",
                     r["model_version_id"], r["held_out_accuracy"], r["n_feedback_examples"],
                     r["drift_score"], r["promoted"])
        except Exception:
            log.exception("second-opinion retrain run failed")
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="loop on an interval (the compose service)")
    ap.add_argument("--interval", type=int, default=settings.retrain_interval_seconds,
                    help="live-mode interval, seconds (default: weekly)")
    args = ap.parse_args()
    if args.live:
        logging.basicConfig(level=logging.INFO)
        _live_loop(args.interval)
    else:
        print(run_once())


if __name__ == "__main__":  # python -m app.triage.retrain
    main()
