"""D1 runner. Its own process — never imported by uvicorn (plan Section 0.5).

File mode (ad-hoc):
    python -m detectors.authlog.run --log /var/log/auth.log
    python -m detectors.authlog.run --log auth.log --dry-run

Live mode (the `detector-authlog` docker-compose service):
    python -m detectors.authlog.run --live --interval 600

Live mode polls the Wazuh alerts index for auth-log lines, fits the anomaly
model on the older part of the fetched window, scores the windows newer than
its cursor, and ingests any flagged one. A `DetectorCursor` row tracks
"scored up to here" + last-run time so a scheduled run doesn't re-score the
same windows and the dashboard can tell it's alive.
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

from detectors.authlog.emit import flagged_alerts, ingest_with_retry
from detectors.authlog.features import DEFAULT_WINDOW_SECONDS, window_features
from detectors.authlog.model import DEFAULT_Z, AuthLogAnomalyModel
from detectors.authlog.parse import iter_events, new_miner
from detectors.authlog.source import fetch_auth_lines

_MIN_WINDOWS = 10          # below this there isn't enough history to model a baseline
_FETCH_HOURS = 24         # how much history each live run pulls for the baseline
_BASELINE_FRAC = 0.7      # first run (no cursor): fit on this fraction, score the rest

log = logging.getLogger("uvicorn.error")


def _split(rows, score_from):
    """(baseline, recent). Windows older than `score_from` train; the rest are
    scored. First run (`score_from=None`) or too-little history -> fraction split."""
    if score_from is not None:
        baseline = [r for r in rows if r.window_start < score_from]
        recent = [r for r in rows if r.window_start >= score_from]
        if len(baseline) >= 2 and recent:
            return baseline, recent
    cut = max(2, int(len(rows) * _BASELINE_FRAC))
    return rows[:cut], rows[cut:]


def run(lines, *, window_seconds: int = DEFAULT_WINDOW_SECONDS, baseline_frac: float = _BASELINE_FRAC,
        z: float = DEFAULT_Z, dry_run: bool = False) -> list[dict]:
    """File mode: score a whole log, ingest flagged windows."""
    rows = window_features(iter_events(lines, miner=new_miner()), window_seconds=window_seconds)
    if len(rows) < _MIN_WINDOWS:
        print(f"only {len(rows)} windows — need more history to model a baseline", file=sys.stderr)
        return []
    cut = max(2, int(len(rows) * baseline_frac))
    model = AuthLogAnomalyModel(z=z).fit(rows[:cut])
    alerts = flagged_alerts(model.score(rows[cut:]), window_seconds=window_seconds, z_threshold=z)
    for a in alerts:
        print(f"flag {a['id']}  {a['rule']['description']}")
    if alerts and not dry_run:
        n = ingest_with_retry(alerts)
        print(f"ingested {n} new anomaly alert(s), {len(alerts) - n} already present")
    return alerts


def live_once(*, client=None, now: datetime | None = None, interval_seconds: int = 600) -> dict:
    """One scheduled pass. Fetches from the alerts index, scores past the cursor,
    ingests, advances the cursor. Returns a small summary dict."""
    from app.db.models import DetectorCursor
    from app.db.session import get_session, init_db

    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    init_db()
    with get_session() as s:
        cur = s.get(DetectorCursor, "authlog") or DetectorCursor(detector="authlog")
        lines = fetch_auth_lines(now - timedelta(hours=_FETCH_HOURS), client=client)
        rows = window_features(iter_events(lines, miner=new_miner()))

        emitted = 0
        if len(rows) >= _MIN_WINDOWS:
            baseline, recent = _split(rows, cur.last_ts)
            if baseline and recent:
                model = AuthLogAnomalyModel().fit(baseline)
                alerts = flagged_alerts(model.score(recent))
                emitted = ingest_with_retry(alerts) if alerts else 0
                cur.last_ts = max(r.window_start for r in recent)

        cur.last_run_at = now
        cur.interval_seconds = interval_seconds
        cur.alerts_emitted += emitted
        s.add(cur)
        s.commit()
        return {"fetched": len(lines), "windows": len(rows), "emitted": emitted,
                "cursor": cur.last_ts.isoformat() if cur.last_ts else None}


def _live_loop(interval: int) -> None:
    log.info("authlog detector: live, every %ss", interval)
    while True:
        try:
            r = live_once(interval_seconds=interval)
            log.info("authlog detector: fetched=%s windows=%s emitted=%s cursor=%s",
                     r["fetched"], r["windows"], r["emitted"], r["cursor"])
        except Exception:
            log.exception("authlog detector run failed")
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="auth-log file (file mode; default stdin)")
    ap.add_argument("--live", action="store_true", help="poll the Wazuh alerts index on an interval")
    ap.add_argument("--interval", type=int, default=600, help="live-mode poll interval, seconds")
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    ap.add_argument("--baseline-frac", type=float, default=_BASELINE_FRAC)
    ap.add_argument("--z", type=float, default=DEFAULT_Z)
    ap.add_argument("--dry-run", action="store_true", help="file mode: score and print, don't ingest")
    args = ap.parse_args()

    if args.live:
        logging.basicConfig(level=logging.INFO)
        _live_loop(args.interval)
        return

    src = open(args.log, encoding="utf-8", errors="replace") if args.log else sys.stdin
    try:
        run(src.read().splitlines(), window_seconds=args.window_seconds,
            baseline_frac=args.baseline_frac, z=args.z, dry_run=args.dry_run)
    finally:
        if args.log:
            src.close()


if __name__ == "__main__":
    main()
