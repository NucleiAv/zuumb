"""D2 step 2: find beaconing — a source calling one (dst, port) on a near-fixed
interval. Deterministic scan, no model:

  group connections by (src_ip, dst_ip, dst_port)
  -> for each group with enough hits over a long enough span,
     measure the coefficient of variation of the inter-arrival gaps
  -> low CV = regular = beacon-like

This is a classic C2-hunt heuristic (RITA / Zeek known-beacons do the same),
and it is intentionally a different *method* from D1's outlier scoring so D2
proves the pipeline is source- and technique-agnostic, not just a second copy
of the same detector.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from statistics import fmean, pstdev

MIN_HITS = 6            # need at least this many connections to call it a pattern
MAX_CV = 0.20          # inter-arrival gaps must stay within ~20% of their mean
MIN_SPAN_SECONDS = 600  # ...sustained over at least this long (not a quick burst)


@dataclass(frozen=True)
class Beacon:
    src_ip: str
    dst_ip: str
    dst_port: int
    hits: int
    mean_gap_seconds: float
    cv: float                 # std/mean of the gaps; lower = more regular
    span_seconds: float
    first_ts: datetime
    last_ts: datetime
    score: float              # regularity * log2(hits); higher = more beacon-like


def find_beacons(conns, *, min_hits: int = MIN_HITS, max_cv: float = MAX_CV,
                 min_span_seconds: float = MIN_SPAN_SECONDS) -> list[Beacon]:
    groups: dict[tuple[str, str, int], list[datetime]] = defaultdict(list)
    for c in conns:
        groups[(c.src_ip, c.dst_ip, c.dst_port)].append(c.ts)

    out: list[Beacon] = []
    for (src, dst, port), times in groups.items():
        if len(times) < min_hits:
            continue
        times.sort()
        span = (times[-1] - times[0]).total_seconds()
        if span < min_span_seconds:
            continue
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean_gap = fmean(gaps)
        if mean_gap <= 0:
            continue
        cv = pstdev(gaps) / mean_gap
        if cv > max_cv:
            continue
        score = round((1 - cv) * math.log2(len(times)), 3)
        out.append(Beacon(src, dst, port, len(times), round(mean_gap, 1), round(cv, 4),
                          round(span, 1), times[0], times[-1], score))
    return sorted(out, key=lambda b: b.score, reverse=True)
