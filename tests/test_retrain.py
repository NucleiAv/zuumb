"""D4: the second-opinion retrain loop — label source, held-out gate, promotion,
drift, and the end-to-end wire-up back into second_opinion.py."""
from datetime import datetime

from sqlmodel import select

from app.config import settings
from app.db.models import Alert, AnalystFeedback, ModelVersion, Verdict
from app.db.session import get_session
from app.triage import second_opinion as so
from app.triage.second_opinion import eval_examples
from app.triage.retrain import (
    _eval_split,
    drift_score,
    feedback_examples,
    promote_if_better,
    run_once,
    train_candidate,
)


def _dummy_pipe():
    """A cheaply-fitted pipeline — enough to exercise persistence, not accuracy."""
    from app.triage.retrain import new_pipeline
    p = new_pipeline()
    p.fit(["benign log line", "malicious exploit attempt"], ["benign", "malicious"])
    return p


def _seed_correction(session, label="malicious"):
    a = Alert(wazuh_alert_id=f"fb-{label}-{id(object())}", timestamp=datetime(2026, 1, 1),
             rule_id="1", rule_description="d", raw_json="{}")
    session.add(a); session.commit(); session.refresh(a)
    v = Verdict(alert_id=a.id, verdict="benign", confidence=0.5, reasoning_text="x", model_version="t")
    session.add(v); session.commit(); session.refresh(v)
    fb = AnalystFeedback(verdict_id=v.id, analyst_verdict=label)
    session.add(fb); session.commit()
    return a, v, fb


# --- eval split --------------------------------------------------------------

def test_eval_split_is_stratified_and_stable_across_calls():
    train1, held1 = _eval_split()
    train2, held2 = _eval_split()
    assert train1 == train2 and held1 == held2       # same seed -> same rows every time
    assert len(train1) + len(held1) == len(eval_examples())
    labels = {lbl for _, lbl in held1}
    assert labels <= {"benign", "suspicious", "malicious"} and len(held1) >= 3


# --- feedback as a label source --------------------------------------------

def test_feedback_examples_empty_with_no_corrections():
    with get_session() as s:
        assert feedback_examples(s) == []


def test_feedback_examples_reads_the_analyst_corrected_label():
    with get_session() as s:
        _seed_correction(s, label="malicious")
        examples = feedback_examples(s)
    assert len(examples) == 1
    text, label = examples[0]
    assert label == "malicious" and isinstance(text, str) and text


# --- training + drift --------------------------------------------------------

def test_train_candidate_uses_the_held_out_set_and_counts_feedback():
    with get_session() as s:
        _seed_correction(s)
        pipe, accuracy, n_feedback, train_texts = train_candidate(s)
    assert 0.0 <= accuracy <= 1.0
    assert n_feedback == 1
    assert len(train_texts) > 27          # eval-train split (~27) + 1 feedback row


def test_drift_score_is_none_with_too_little_recent_traffic():
    with get_session() as s:
        pipe, _, _, train_texts = train_candidate(s)
        assert drift_score(pipe, train_texts, s) is None


def test_drift_score_is_high_when_recent_traffic_matches_training_text():
    with get_session() as s:
        pipe, _, _, train_texts = train_candidate(s)
        for i in range(25):
            s.add(Alert(wazuh_alert_id=f"drift-{i}", timestamp=datetime(2026, 1, 1),
                        rule_id="1", rule_description=train_texts[i % len(train_texts)],
                        raw_json="{}"))
        s.commit()
        score = drift_score(pipe, train_texts, s)
    assert score is not None and score > 0.3   # not identical text (brief != rule_description) but related


# --- promotion gate: the actual "never regress" behaviour ------------------

def test_first_run_always_promotes(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "model_dir", str(tmp_path))
    with get_session() as s:
        row = promote_if_better(s, _dummy_pipe(), 0.5, 0, None)
    assert row.promoted is True and row.path
    assert (tmp_path / row.path).exists()


def test_worse_candidate_is_rejected_incumbent_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "model_dir", str(tmp_path))
    with get_session() as s:
        first = promote_if_better(s, _dummy_pipe(), 0.8, 0, None)
    with get_session() as s:
        worse = promote_if_better(s, _dummy_pipe(), 0.5, 5, None)
        assert worse.promoted is False and worse.path == ""
        current = s.exec(
            select(ModelVersion).where(ModelVersion.kind == "second_opinion",
                                       ModelVersion.promoted == True)  # noqa: E712
        ).one()
        assert current.id == first.id and current.held_out_accuracy == 0.8


def test_equal_or_better_candidate_promotes_and_demotes_incumbent(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "model_dir", str(tmp_path))
    with get_session() as s:
        first = promote_if_better(s, _dummy_pipe(), 0.5, 0, None)
    with get_session() as s:
        better = promote_if_better(s, _dummy_pipe(), 0.7, 3, None)
        assert better.promoted is True
        old = s.get(ModelVersion, first.id)
        assert old.promoted is False


# --- end to end: run_once() wires back into second_opinion.py --------------

def test_run_once_promotes_and_second_opinion_then_uses_it(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "model_dir", str(tmp_path))
    so._model.cache_clear()
    try:
        with get_session() as s:
            _seed_correction(s, label="malicious")
        r = run_once()
        assert r["promoted"] is True and r["n_feedback_examples"] == 1

        promoted = so._load_promoted()
        assert promoted is not None
        label, conf = so.second_opinion("some alert text")
        assert label in so.LABELS and 0.0 < conf <= 1.0
    finally:
        so._model.cache_clear()
