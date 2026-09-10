"""D1 step 1: turn raw auth-log lines into stable event templates.

No model, no scoring, no alerts yet. This module only does the parsing and
template-mining every later D1 step builds on:

    raw syslog line  ->  (ts, host, program, message)  ->  template id + string

"Failed password for invalid user oracle from 198.51.100.69 port 54661 ssh2" and
the same line with a different user/ip/port collapse to one template, so later
steps can count *template* rates instead of drowning in unique strings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

# "Sep 10 17:38:09 agent-lab-01 sshd[644]: Failed password for invalid user ..."
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass(frozen=True)
class Event:
    """One parsed + templated log line."""
    ts: datetime          # naive UTC; syslog carries no year, so it's inferred
    host: str
    program: str
    message: str
    template_id: int
    template: str


def parse_syslog_line(raw: str, *, now: datetime | None = None) -> tuple[datetime, str, str, str] | None:
    """`(ts, host, program, message)` from one BSD-syslog line, or None if it
    doesn't parse. Syslog has no year: assume the current one, roll back a year
    if that lands the timestamp more than a day in the future (log rotation)."""
    m = _SYSLOG.match(raw.strip())
    if not m:
        return None
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    hh, mm, ss = (int(x) for x in m["time"].split(":"))
    ts = datetime(now.year, _MONTHS[m["mon"]], int(m["day"]), hh, mm, ss)
    if ts - now > timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts, m["host"], m["prog"], m["msg"]


def new_miner() -> TemplateMiner:
    """A Drain3 miner tuned for auth logs: IPs and bare numbers are masked before
    clustering so `... from <ip> port <num> ssh2` is one template, not thousands."""
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    cfg.drain_sim_th = 0.4
    cfg.masking_instructions = [
        MaskingInstruction(r"((\d{1,3}\.){3}\d{1,3})", "ip"),
        MaskingInstruction(r"\d+", "num"),
    ]
    return TemplateMiner(config=cfg)


def iter_events(lines, *, miner: TemplateMiner | None = None, now: datetime | None = None):
    """Yield an `Event` per parsable line, mining templates as it goes.
    Unparsable lines are skipped. Pass a shared `miner` to keep the template
    vocabulary stable across calls."""
    miner = miner or new_miner()
    for raw in lines:
        parsed = parse_syslog_line(raw, now=now)
        if parsed is None:
            continue
        ts, host, program, message = parsed
        res = miner.add_log_message(message)
        yield Event(ts, host, program, message, res["cluster_id"], res["template_mined"])
