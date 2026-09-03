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
# `confirm` actions need a second explicit confirmation before they dispatch.
ACTIONS: dict[str, dict] = {
    "block-ip": {"command": "!firewall-drop", "target": "ip", "confirm": False,
                 "label": "Block source IP (firewall-drop)"},
    "disable-user": {"command": "!disable-account", "target": "user", "confirm": True,
                     "label": "Disable account (disable-account)"},
}


def _token(client: httpx.Client) -> str:
    r = client.post(
        f"{settings.wazuh_ar_api_url.rstrip('/')}/security/user/authenticate",
        auth=(settings.wazuh_ar_api_user, settings.wazuh_ar_api_password),
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def dispatch(action: str, target: str, agent_id: str, *,
             client: httpx.Client | None = None) -> dict:
    """PUT /active-response for one allowlisted action. Never called in dry-run.
    Returns {ok, status_code, text}."""
    if action not in ACTIONS:
        raise ValueError(f"action not in allowlist: {action!r}")
    own = client is None
    client = client or httpx.Client(verify=settings.wazuh_verify_ssl, timeout=30)
    try:
        base = settings.wazuh_ar_api_url.rstrip("/")
        headers = {"Authorization": f"Bearer {_token(client)}"}
        body = {
            "command": ACTIONS[action]["command"],
            "arguments": [target],
            "alert": {"data": {"srcip": target}},
        }
        r = client.put(f"{base}/active-response?agents_list={agent_id}",
                       headers=headers, json=body)
        return {"ok": r.status_code < 300, "status_code": r.status_code, "text": r.text}
    finally:
        if own:
            client.close()
