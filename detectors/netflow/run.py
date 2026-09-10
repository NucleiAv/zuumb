"""D2 runner. Its own process — never imported by uvicorn (plan Section 0.5).

    python -m detectors.netflow.run --conn conn.log --host web-01
    python -m detectors.netflow.run --conn flows.csv --dry-run

Reads connection records, finds regular-interval beacons, ingests each as an
alert via the shared path. Re-runs are safe: the same day's beacon hashes to
the same id and ingest dedupe absorbs it.
"""
from __future__ import annotations

import argparse
import sys

from detectors.ingest import ingest_with_retry
from detectors.netflow.beacon import MAX_CV, MIN_HITS, MIN_SPAN_SECONDS, find_beacons
from detectors.netflow.emit import beacon_alerts
from detectors.netflow.parse import parse_conn_log


def run(lines, *, host: str | None = None, min_hits: int = MIN_HITS, max_cv: float = MAX_CV,
        min_span_seconds: float = MIN_SPAN_SECONDS, dry_run: bool = False) -> list[dict]:
    conns = parse_conn_log(lines)
    beacons = find_beacons(conns, min_hits=min_hits, max_cv=max_cv,
                           min_span_seconds=min_span_seconds)
    alerts = beacon_alerts(beacons, host=host)
    for b, a in zip(beacons, alerts):
        print(f"beacon {a['id']}  {a['rule']['description']}")
    if alerts and not dry_run:
        n = ingest_with_retry(alerts)
        print(f"ingested {n} new beacon alert(s), {len(alerts) - n} already present")
    return alerts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", help="connection log (Zeek conn.log or ts,src,dst,port CSV); default stdin")
    ap.add_argument("--host", help="vantage-point host name for the emitted alerts")
    ap.add_argument("--min-hits", type=int, default=MIN_HITS)
    ap.add_argument("--max-cv", type=float, default=MAX_CV)
    ap.add_argument("--min-span-seconds", type=float, default=MIN_SPAN_SECONDS)
    ap.add_argument("--dry-run", action="store_true", help="score and print, don't ingest")
    args = ap.parse_args()

    src = open(args.conn, encoding="utf-8", errors="replace") if args.conn else sys.stdin
    try:
        run(src.read().splitlines(), host=args.host, min_hits=args.min_hits, max_cv=args.max_cv,
            min_span_seconds=args.min_span_seconds, dry_run=args.dry_run)
    finally:
        if args.conn:
            src.close()


if __name__ == "__main__":
    main()
