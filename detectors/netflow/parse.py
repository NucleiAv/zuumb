"""D2 step 1: parse connection records into `Conn` rows.

Accepts two shapes, both common in the wild:
  - Zeek `conn.log` (TSV with a `#fields` header line)
  - a headerless CSV/TSV of `ts, src_ip, dst_ip, dst_port[, proto[, bytes]]`
`ts` may be epoch seconds or ISO-8601. Unparsable lines are skipped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

# Zeek conn.log columns we pull, in the positional order `_row` expects.
_ZEEK_COLS = ("ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "orig_bytes")


@dataclass(frozen=True)
class Conn:
    ts: datetime          # naive UTC
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    orig_bytes: int = 0


def _to_dt(raw: str) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(raw), timezone.utc).replace(tzinfo=None)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(raw)
        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        return None


def _row(cols: list[str]) -> Conn | None:
    if len(cols) < 4:
        return None
    ts = _to_dt(cols[0])
    if ts is None:
        return None
    try:
        port = int(cols[3])
    except ValueError:
        return None
    proto = cols[4] if len(cols) > 4 and cols[4] not in ("-", "") else "tcp"
    try:
        obytes = int(cols[5]) if len(cols) > 5 and cols[5] not in ("-", "") else 0
    except ValueError:
        obytes = 0
    return Conn(ts, cols[1], cols[2], port, proto, obytes)


def parse_conn_log(lines) -> list[Conn]:
    fields: list[str] | None = None
    out: list[Conn] = []
    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t") if "\t" in line else re.split(r"\s*,\s*|\s+", line.strip())
        if fields:  # Zeek: pull the columns we care about into positional order
            idx = {f: i for i, f in enumerate(fields)}
            try:
                cols = [cols[idx[z]] for z in _ZEEK_COLS]
            except (KeyError, IndexError):
                continue
        conn = _row(cols)
        if conn is not None:
            out.append(conn)
    return out
