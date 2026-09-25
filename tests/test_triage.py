from datetime import datetime
from types import SimpleNamespace

import pytest
from sqlmodel import select

from app.db.models import Alert, Verdict
from app.db.session import get_session, init_db
from app.system_settings import set_ai_triage_enabled
from app.triage.agent import _alert_brief, _extract_verdict, triage_alert


def _make_alert(**over) -> Alert:
    init_db()
    a = Alert(
        wazuh_alert_id=over.get("wid", "t-1"),
        timestamp=datetime(2026, 8, 28, 14, 7),
        rule_id="5715",
        rule_description="sshd: authentication success.",
        agent_name="web-01",
        src_ip="203.0.113.44",
        user="www-data",
        raw_json="{}",
    )
    with get_session() as s:
        s.add(a)
        s.commit()
        s.refresh(a)
    return a


def test_extract_reads_tool_use():
    content = [
        SimpleNamespace(type="text", text="thinking"),
        SimpleNamespace(type="tool_use", input={"verdict": "benign", "confidence": 0.9}),
    ]
    assert _extract_verdict(content)["verdict"] == "benign"


def test_extract_raises_without_tool_use():
    with pytest.raises(RuntimeError):
        _extract_verdict([SimpleNamespace(type="text", text="hi")])


def test_alert_brief_omits_empty_fields():
    brief = _alert_brief(_make_alert(wid="t-brief"))
    assert "rule_id: 5715" in brief
    assert "dst_ip" not in brief  # None -> omitted


def test_triage_writes_verdict_row():
    alert = _make_alert(wid="t-write")
    fake = lambda system, user: {  # noqa: E731
        "verdict": "malicious",
        "confidence": 0.92,
        "reasoning": "Reverse shell listener opened by www-data.",
        "mitre_technique": "T1059",
    }
    v = triage_alert(alert, call=fake)
    assert v.id is not None
    assert (v.verdict, v.mitre_technique) == ("malicious", "T1059")
    assert v.model_version  # set from settings
    with get_session() as s:
        rows = s.exec(select(Verdict).where(Verdict.alert_id == alert.id)).all()
    assert len(rows) == 1 and rows[0].confidence == 0.92


def test_triage_rejects_unpersisted_alert():
    with pytest.raises(ValueError):
        triage_alert(Alert(wazuh_alert_id="x", timestamp=None, rule_id="1",
                           rule_description="d", raw_json="{}"), call=lambda s, u: {})


def test_triage_marks_the_verdict_source_llm_by_default():
    alert = _make_alert(wid="t-src-llm")
    fake = lambda system, user: {  # noqa: E731
        "verdict": "benign", "confidence": 0.5, "reasoning": "x", "mitre_technique": None,
    }
    v = triage_alert(alert, call=fake)
    assert v.verdict_source == "llm"


def test_triage_skips_the_llm_when_ai_detection_is_off():
    alert = _make_alert(wid="t-ai-off")
    with get_session() as s:
        set_ai_triage_enabled(s, False)

    def fake(system, user):
        raise AssertionError("the LLM must not be called while AI detection is off")

    v = triage_alert(alert, call=fake)
    assert v.verdict_source == "ml_fallback"
    assert v.model_version == "second_opinion"
    assert v.verdict in ("benign", "suspicious", "malicious")
    assert v.second_opinion is None  # nothing to cross-check the fallback against itself
    assert "AI detection is switched off" in v.reasoning_text


def test_triage_resumes_the_llm_once_ai_detection_is_back_on():
    alert = _make_alert(wid="t-ai-back-on")
    with get_session() as s:
        set_ai_triage_enabled(s, False)
        set_ai_triage_enabled(s, True)
    fake = lambda system, user: {  # noqa: E731
        "verdict": "suspicious", "confidence": 0.6, "reasoning": "x", "mitre_technique": None,
    }
    v = triage_alert(alert, call=fake)
    assert v.verdict_source == "llm" and v.verdict == "suspicious"
