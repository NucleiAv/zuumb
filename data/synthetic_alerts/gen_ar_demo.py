"""Generate data/synthetic_alerts/ar_demo.jsonl — two incidents that each yield a
one-click active-response task, so the Phase 14 approve -> dispatch flow is easy
to exercise:

  * SSH brute force from 203.0.113.99  -> "Block the source IP..."  (block-ip)
  * valid-account abuse by user mallory -> "Rotate or disable the..." (disable-user, confirm twice)

`agent.id` must match a REAL enrolled agent for a live dispatch (dry-run works
with any id). Default 006 = agent-lab-01; check `agent_control -l` and override:

    AGENT_ID=007 python data/synthetic_alerts/gen_ar_demo.py
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path

AID = os.environ.get("AGENT_ID", "006")
AGENT_NAME = os.environ.get("AGENT_NAME", "agent-lab-01")
DAY0 = datetime(2026, 9, 3, 20, 0)
OUT = Path(__file__).with_name("ar_demo.jsonl")
_n = 0


def A(minute, rule_id, desc, mitre_id, tactic, data, full_log):
    global _n
    _n += 1
    return {
        "timestamp": (DAY0 + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%S") + ".000+0000",
        "id": f"ard-{_n:03d}",
        "rule": {"id": str(rule_id), "level": 10, "description": desc,
                 "groups": ["attack", "authentication_failures"],
                 "mitre": {"id": [mitre_id], "tactic": [tactic]}},
        "agent": {"id": AID, "name": AGENT_NAME},
        "manager": {"name": "wazuh.manager"},
        "decoder": {"name": "synthetic"},
        "data": data,
        "full_log": full_log,
        "location": "/var/log/synthetic",
    }


rows = []
# incident 1 — SSH brute force from one IP -> block-ip task
for i in range(6):
    rows.append(A(i, 5712, "sshd: possible brute force attack (multiple auth failures).",
                  "T1110", "Credential Access",
                  {"srcip": "203.0.113.99", "srcuser": "root"},
                  "maximum authentication attempts exceeded for root from 203.0.113.99"))
# incident 2 — >30 min later (own incident): account 'mallory' added then used -> disable-user
rows.append(A(45, 5902, "New user 'mallory' added to the system (useradd).",
              "T1078", "Persistence", {"srcip": "203.0.113.99", "dstuser": "mallory"},
              "new user: name=mallory, UID=0, GID=0, home=/root"))
rows.append(A(47, 5501, "PAM: Login session opened.", "T1078", "Persistence",
             {"srcip": "203.0.113.99", "dstuser": "mallory"},
             "session opened for user mallory(uid=0) by (uid=0)"))

OUT.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
print(f"wrote {len(rows)} alerts (agent {AID}) -> {OUT.name}")
