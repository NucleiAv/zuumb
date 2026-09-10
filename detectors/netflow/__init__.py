"""D2 network-beacon detector — the second detection engine.

Deliberately unlike D1 in both data and method: it reads connection records
(Zeek `conn.log` or a plain CSV of `ts,src,dst,port`), not log text, and it
flags *regularity* — a source that calls one destination on a near-fixed
interval, the signature of C2 beaconing — with a deterministic statistical
scan, not a trained anomaly model.

Its only job, like D1's, is to emit alerts in the `normalize_alert` shape and
push them through `detectors.ingest`. Nothing in zuumb's core changes to accept
them. `rule.id` sits in D2's reserved 901001-901999 band (plan Section 0.5).

    ts src_ip dst_ip dst_port  ->  Conn
    Conns                      ->  Beacon findings (regular-interval callbacks)
    Beacon                     ->  Wazuh-shaped alert dict  ->  ingest
"""
from detectors.netflow.beacon import Beacon, find_beacons
from detectors.netflow.emit import D2_RULE_ID, beacon_alerts, beacon_to_alert
from detectors.netflow.parse import Conn, parse_conn_log

__all__ = [
    "Conn", "parse_conn_log",
    "Beacon", "find_beacons",
    "beacon_to_alert", "beacon_alerts", "D2_RULE_ID",
]
