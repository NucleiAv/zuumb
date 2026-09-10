"""Mask obvious secrets in free text before it leaves the DB (to the LLM, or to
the alert-detail UI). High precision on purpose: real triage signal such as
payloads and file hashes still passes through. This is scoping, not scrubbing.
"""
from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
                r"auth(?:orization)?)\b\s*[=:]\s*\S+"), r"\1=[redacted]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"), "Bearer [redacted]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[redacted-aws-key]"),
]


def redact(s: str) -> str:
    for pat, repl in _PATTERNS:
        s = pat.sub(repl, s)
    return s
