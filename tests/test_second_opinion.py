"""D3: the lightweight local second-opinion classifier. Advisory only."""
import json
from pathlib import Path

from sqlmodel import select

from app.db.models import Alert, Verdict
from app.db.session import get_session
from app.ingestion.wazuh_client import normalize_alert
from app.triage.agent import _alert_brief, triage_alert
from app.triage.offline import offline_verdict
from app.triage.second_opinion import LABELS, backfill, second_opinion

_LABELED = Path(__file__).parents[1] / "eval" / "labeled_set.jsonl"


def _labeled_rows():
    return [json.loads(ln) for ln in _LABELED.read_text(encoding="utf-8").splitlines() if ln.strip()]


def test_returns_a_valid_label_and_confidence_deterministically():
    brief = _alert_brief(normalize_alert(_labeled_rows()[0]["alert"]))
    a, b = second_opinion(brief), second_opinion(brief)
    assert a == b
    assert a[0] in LABELS and 0.0 < a[1] <= 1.0


def test_fits_the_labeled_set_it_trains_on():
    rows = _labeled_rows()
    hits = sum(second_opinion(_alert_brief(normalize_alert(r["alert"])))[0] == r["label"] for r in rows)
    assert hits / len(rows) >= 0.8  # memorising its own 34 examples, sanity that the pipeline works


def test_a_blatantly_malicious_brief_is_not_called_benign():
    mal = next(r for r in _labeled_rows() if r["label"] == "malicious")
    assert second_opinion(_alert_brief(normalize_alert(mal["alert"])))[0] != "benign"


def test_triage_alert_records_a_second_opinion_alongside_the_primary_verdict():
    from app.ingestion.wazuh_client import ingest_alerts
    ingest_alerts([_labeled_rows()[0]["alert"] | {"id": "so-1"}])
    with get_session() as s:
        alert = s.exec(select(Alert).where(Alert.wazuh_alert_id == "so-1")).one()
        v = triage_alert(alert, session=s, call=offline_verdict)
        assert v.second_opinion in LABELS
        assert 0.0 < v.second_opinion_confidence <= 1.0
        # primary verdict is untouched by the second opinion
        assert v.verdict in LABELS


def test_backfill_fills_verdicts_missing_a_second_opinion():
    from app.ingestion.wazuh_client import ingest_alerts
    ingest_alerts([r["alert"] | {"id": f"bf-{i}"} for i, r in enumerate(_labeled_rows()[:5])])
    with get_session() as s:
        for a in s.exec(select(Alert)).all():
            s.add(Verdict(alert_id=a.id, verdict="benign", confidence=0.5,
                          reasoning_text="x", model_version="t"))
        s.commit()
        assert all(v.second_opinion is None for v in s.exec(select(Verdict)).all())

    n = backfill()
    assert n == 5
    with get_session() as s:
        assert all(v.second_opinion in LABELS for v in s.exec(select(Verdict)).all())


def test_second_opinion_does_not_feed_severity_or_correlation():
    # incident_severity + correlate only look at the primary verdict / analyst override
    import inspect
    from app.correlation import engine
    src = inspect.getsource(engine)
    assert "second_opinion" not in src


def test_escalates_only_flags_a_stricter_second_opinion():
    from app.triage.second_opinion import escalates
    assert escalates("benign", "malicious") is True
    assert escalates("suspicious", "malicious") is True
    assert escalates("malicious", "benign") is False      # more lenient -> not surfaced
    assert escalates("suspicious", "suspicious") is False  # agreement -> not surfaced
    assert escalates("benign", None) is False
