"""D1 step 2: turn a stream of templated Events into per-window feature rows.

One row per (host, fixed time window). Features are frequencies only — total
events, distinct templates, a per-minute rate, and the count of each template
in the window. That's the input Isolation Forest wants in step 3: "how much of
each kind of line happened on this host in this five minutes." No sequence
modelling here (that would be a later deep-loglizer-style upgrade); counts are
enough to make a brute-force burst stand out from a quiet window.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from detectors.authlog.parse import Event

DEFAULT_WINDOW_SECONDS = 300


@dataclass(frozen=True)
class FeatureRow:
    host: str
    window_start: datetime          # bucket start, naive UTC (matches how zuumb stores time)
    n_events: int
    n_distinct_templates: int
    events_per_min: float
    template_counts: dict[int, int]  # template_id -> count within this window


def _bucket_start(ts: datetime, window_seconds: int) -> datetime:
    """Floor a timestamp to its window boundary. `ts` is treated as UTC."""
    epoch = int(ts.replace(tzinfo=timezone.utc).timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, timezone.utc).replace(tzinfo=None)


def window_features(events, *, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list[FeatureRow]:
    """Group `Event`s into (host, window) buckets, one `FeatureRow` each.
    Events need not be sorted; rows are returned ordered by (host, window_start)."""
    buckets: dict[tuple[str, datetime], list[int]] = defaultdict(list)
    for e in events:
        buckets[(e.host, _bucket_start(e.ts, window_seconds))].append(e.template_id)

    rows: list[FeatureRow] = []
    for (host, start), tids in sorted(buckets.items()):
        counts = Counter(tids)
        rows.append(FeatureRow(
            host=host,
            window_start=start,
            n_events=len(tids),
            n_distinct_templates=len(counts),
            events_per_min=round(len(tids) / (window_seconds / 60), 3),
            template_counts=dict(counts),
        ))
    return rows


def template_vocabulary(rows) -> list[int]:
    """Every template_id seen across `rows`, sorted. This is the column order a
    model vectorizes `template_counts` against in step 3, so it must be stable."""
    return sorted({tid for r in rows for tid in r.template_counts})
