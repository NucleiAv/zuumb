"""D1 step 4: standalone runner. Its own process — never imported by uvicorn.

    python -m detectors.authlog.run --log /var/log/auth.log
    python -m detectors.authlog.run --log auth.log --dry-run

Reads auth-log lines, mines templates, builds per-window features, fits the
anomaly model on the older `baseline-frac` of windows, scores the rest, and
ingests any flagged window as an alert via the normal zuumb ingest path.
Re-runs are safe: a window that is still flagged produces the same alert id
and ingest dedupe absorbs it.
"""
from __future__ import annotations

import argparse
import sys

from detectors.authlog.emit import flagged_alerts, ingest_with_retry
from detectors.authlog.features import DEFAULT_WINDOW_SECONDS, window_features
from detectors.authlog.model import DEFAULT_Z, AuthLogAnomalyModel
from detectors.authlog.parse import iter_events, new_miner

_MIN_WINDOWS = 10  # below this there isn't enough history to model a baseline


def run(lines, *, window_seconds: int = DEFAULT_WINDOW_SECONDS, baseline_frac: float = 0.7,
        z: float = DEFAULT_Z, dry_run: bool = False) -> list[dict]:
    rows = window_features(iter_events(lines, miner=new_miner()), window_seconds=window_seconds)
    if len(rows) < _MIN_WINDOWS:
        print(f"only {len(rows)} windows — need more history to model a baseline", file=sys.stderr)
        return []

    cut = max(2, int(len(rows) * baseline_frac))
    model = AuthLogAnomalyModel(z=z).fit(rows[:cut])
    scored = model.score(rows[cut:])
    alerts = flagged_alerts(scored, window_seconds=window_seconds, z_threshold=z)

    for a in alerts:
        print(f"flag {a['id']}  {a['rule']['description']}")
    if alerts and not dry_run:
        n = ingest_with_retry(alerts)
        print(f"ingested {n} new anomaly alert(s), {len(alerts) - n} already present")
    return alerts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="auth-log file (default: stdin)")
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    ap.add_argument("--baseline-frac", type=float, default=0.7)
    ap.add_argument("--z", type=float, default=DEFAULT_Z)
    ap.add_argument("--dry-run", action="store_true", help="score and print, don't ingest")
    args = ap.parse_args()

    src = open(args.log, encoding="utf-8", errors="replace") if args.log else sys.stdin
    try:
        run(src.read().splitlines(), window_seconds=args.window_seconds,
            baseline_frac=args.baseline_frac, z=args.z, dry_run=args.dry_run)
    finally:
        if args.log:
            src.close()


if __name__ == "__main__":
    main()
