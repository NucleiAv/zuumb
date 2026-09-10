"""D1 auth-log anomaly detector.

Pipeline, one module per step:
  parse.py     raw syslog line  -> Event (parsed + Drain3 template id)
  features.py  Events           -> FeatureRow per (host, time-window)
  model.py     FeatureRows      -> ScoredWindow (Isolation Forest anomaly score)
  (later)      flagged windows  -> alert via ingest_alerts

Runs as its own process, never inside uvicorn (plan Section 0.5 point 4).
"""
from detectors.authlog.features import FeatureRow, template_vocabulary, window_features
from detectors.authlog.model import AuthLogAnomalyModel, ScoredWindow
from detectors.authlog.parse import Event, iter_events, new_miner, parse_syslog_line

__all__ = [
    "Event", "iter_events", "new_miner", "parse_syslog_line",
    "FeatureRow", "window_features", "template_vocabulary",
    "AuthLogAnomalyModel", "ScoredWindow",
]
