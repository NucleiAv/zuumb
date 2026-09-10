"""ML/DL detection engines that run *in front of* zuumb.

Each detector is a standalone process (never imported into the uvicorn web app,
see zuumb-detection-track-plan.md Section 0.5 point 4). A detector's only job is
to score raw telemetry and hand any hits to zuumb as alerts in the exact shape
`app.ingestion.wazuh_client.normalize_alert` expects, via `ingest_alerts([...])`.
"""
