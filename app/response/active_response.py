"""The ONLY place zuumb dispatches a real response.

Everything here is scoped to Wazuh's Active Response API: one authenticated
`PUT /active-response` per approved action, against a fixed allowlist. No shell,
no SSH/WinRM, no arbitrary command — `tests/test_response.py` enforces that.
Dispatch happens only after a human approves the task; dry-run (config default)
skips the call entirely and just records intent.
"""
from __future__ import annotations

import httpx

from app.config import settings

# Allowlisted actions -> the Wazuh AR script (all ship on the 4.9 agent). The `!`
# prefix runs the named script directly, no manager <active-response> block needed.
# `confirm` -> needs a second explicit confirmation before it dispatches.
ACTIONS: dict[str, dict] = {
    "block-ip": {"command": "!firewall-drop", "confirm": False},
    "disable-user": {"command": "!disable-account", "confirm": True},
}


def dispatch(action: str, target: str, agent_id: str, *,
             client: httpx.Client | None = None) -> dict:
    """PUT /active-response for one allowlisted action. Never called in dry-run.
    Returns {ok, status_code, text}."""
    if action not in ACTIONS:
        raise ValueError(f"action not in allowlist: {action!r}")
    base = settings.wazuh_ar_api_url.rstrip("/")
    own = client is None
    client = client or httpx.Client(verify=settings.wazuh_verify_ssl, timeout=30)
    try:
        auth = client.post(f"{base}/security/user/authenticate",
                           auth=(settings.wazuh_ar_api_user, settings.wazuh_ar_api_password))
        auth.raise_for_status()
        r = client.put(
            f"{base}/active-response?agents_list={agent_id}",
            headers={"Authorization": f"Bearer {auth.json()['data']['token']}"},
            json={"command": ACTIONS[action]["command"], "arguments": [target],
                  "alert": {"data": {"srcip": target}}},
        )
        return {"ok": r.status_code < 300, "status_code": r.status_code, "text": r.text}
    finally:
        if own:
            client.close()
