"""Triage agent: one Alert -> Claude -> a structured Verdict row.

The LLM call is injectable (`call=`) so tests never hit the API.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable

from sqlmodel import Session

from app.config import settings
from app.db.models import Alert, Verdict
from app.db.session import get_session, init_db
from app.feedback.logger import few_shot_block
from app.redact import redact

PROMPT_PATH = Path(__file__).parents[2] / "prompts" / "triage_v1.md"

_TOOL = {
    "name": "record_verdict",
    "description": "Record the triage verdict for one Wazuh alert.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning": {"type": "string"},
            "mitre_technique": {
                "type": ["string", "null"],
                "description": "Best-guess ATT&CK technique id like T1190, or null.",
            },
        },
        "required": ["verdict", "confidence", "reasoning"],
    },
}

LlmCall = Callable[[str, str], dict]


def _alert_brief(a: Alert) -> str:
    """The structured fields triage needs plus the human-readable log line, with
    obvious secrets masked. The full raw alert JSON is deliberately not sent to
    the external model."""
    raw = json.loads(a.raw_json) if a.raw_json else {}
    rule = raw.get("rule", {})
    fields = {
        "timestamp": a.timestamp,
        "rule_id": a.rule_id,
        "rule_description": a.rule_description,
        "rule_groups": ", ".join(rule.get("groups", []) or []),
        "mitre": ", ".join(rule.get("mitre", {}).get("id", []) or []),
        "rule_level": rule.get("level"),
        "agent": a.agent_name,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "user": a.user,
        "log": raw.get("full_log") or raw.get("previous_output") or "",
    }
    return "\n".join(f"{k}: {redact(str(v))}" for k, v in fields.items() if v not in (None, ""))


def _extract_verdict(content) -> dict:
    for block in content:
        if getattr(block, "type", None) == "tool_use":
            return block.input
    raise RuntimeError("model did not return a record_verdict tool call")


def _call_llm(system: str, user: str) -> dict:
    from anthropic import Anthropic  # lazy: no import/key cost in tests

    client = Anthropic(api_key=settings.anthropic_api_key)
    resp = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": user}],
        tools=[_TOOL],
        tool_choice={"type": "tool", "name": "record_verdict"},
    )
    return _extract_verdict(resp.content)


def triage_alert(
    alert: Alert, *, session: Session | None = None, call: LlmCall | None = None
) -> Verdict:
    if alert.id is None:
        raise ValueError("alert must be persisted (alert.id is None)")
    call = call or _call_llm
    init_db()
    own = session is None
    session = session or get_session()
    try:
        system = PROMPT_PATH.read_text(encoding="utf-8") + few_shot_block(session)  # last-K analyst corrections
        brief = _alert_brief(alert)
        out = call(system, brief)
        verdict = Verdict(
            alert_id=alert.id,
            verdict=out["verdict"],
            confidence=float(out["confidence"]),
            reasoning_text=out["reasoning"],
            mitre_technique=out.get("mitre_technique"),
            model_version=settings.anthropic_model,
        )
        try:  # D3: advisory cross-check; must never break the primary verdict
            from app.triage.second_opinion import second_opinion
            verdict.second_opinion, verdict.second_opinion_confidence = second_opinion(brief)
        except Exception as e:  # noqa: BLE001
            logging.getLogger("uvicorn.error").warning("second opinion skipped: %s", e)
        session.add(verdict)
        session.commit()
        session.refresh(verdict)
        return verdict
    finally:
        if own:
            session.close()
