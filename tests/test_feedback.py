from datetime import datetime

import pytest

from app.db.models import Alert, AnalystFeedback, Verdict
from app.db.session import get_session
from app.feedback.logger import few_shot_block, record_override, recent_overrides
from app.triage.agent import triage_alert


def _verdict(s, verdict="benign", rule_desc="sshd: authentication success.") -> Verdict:
    a = Alert(wazuh_alert_id=f"fb-{rule_desc}-{verdict}", timestamp=datetime(2026, 8, 28, 14, 0),
              rule_id="5715", rule_description=rule_desc, agent_name="db-01",
              src_ip="198.51.100.9", user="postgres", raw_json="{}")
    s.add(a)
    s.commit()
    s.refresh(a)
    v = Verdict(alert_id=a.id, verdict=verdict, confidence=0.6,
                reasoning_text="...", model_version="t")
    s.add(v)
    s.commit()
    s.refresh(v)
    return v


def test_record_override_validates_verdict_and_verdict_id():
    with get_session() as s:
        v = _verdict(s)
        with pytest.raises(ValueError):
            record_override(s, v.id, "bogus")
        with pytest.raises(ValueError):
            record_override(s, 999999, "benign")
        fb = record_override(s, v.id, "malicious", "  brute force succeeded  ")
        assert fb.id and fb.analyst_verdict == "malicious" and fb.note == "brute force succeeded"


def test_recent_overrides_newest_first_limited_to_k():
    with get_session() as s:
        for verd in ("benign", "suspicious", "malicious"):
            record_override(s, _verdict(s, verd).id, "malicious")
        rows = recent_overrides(s, k=2)
    assert len(rows) == 2
    assert [v.verdict for _fb, v, _a in rows] == ["malicious", "suspicious"]  # newest first


def test_few_shot_block_empty_without_feedback_then_contains_correction():
    with get_session() as s:
        assert few_shot_block(s) == ""
        v = _verdict(s, "suspicious")
        record_override(s, v.id, "malicious", "successful login after brute force")
        block = few_shot_block(s)
    assert "Recent analyst corrections" in block
    assert "model said suspicious, analyst corrected to malicious" in block
    assert "successful login after brute force" in block


def test_triage_prompt_includes_few_shot_examples():
    seen = {}

    def fake(system, user):
        seen["system"] = system
        return {"verdict": "benign", "confidence": 0.5, "reasoning": "x", "mitre_technique": None}

    with get_session() as s:
        v = _verdict(s, "suspicious")
        record_override(s, v.id, "malicious", "note-xyz")
        target = _verdict(s, "benign", rule_desc="new alert to triage").alert_id
        alert = s.get(Alert, target)
        triage_alert(alert, session=s, call=fake)
    assert "analyst corrected to malicious" in seen["system"]
    assert "note-xyz" in seen["system"]
