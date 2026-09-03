# zuumb
<img width="1895" height="857" alt="image" src="https://github.com/user-attachments/assets/541c9e0c-c63c-4b73-9e84-ec26d7ac97a2" />


An AI-Native Detection & Response (AIDR) layer on top of [Wazuh](https://wazuh.com):
Wazuh alert → LLM triage verdict → entity/time correlation into incidents →
attack chain, response-task proposals, analyst feedback loop, dashboard.

Built as the next layer on top of prior Wazuh detection-rule work.

## Supported versions

| Wazuh | Status |
|-------|--------|
| **4.9.x** | Fully supported. The alert normaliser targets the Wazuh 4.x schema and is tested against a live 4.9.2 single-node stack. |
| **5.x / OCSF** | Not yet supported. The 5.x ECS/OCSF event schema differs from the 4.x schema the normaliser targets. Support is tracked as future work (build plan §11). |

## Prerequisites
- Python 3.11+
- An Anthropic API key ([platform.claude.com](https://platform.claude.com)) — the only paid dependency
- For live polling only: Docker and a Wazuh **4.9.x** single-node stack (setup below)

## Quickstart

```bash
cp .env.example .env           # then put your ANTHROPIC_API_KEY in .env

python -m venv .venv
. .venv/Scripts/activate       # Windows;  ".venv/bin/activate" on macOS/Linux
pip install -r requirements.txt
pytest -q
```

Run it on synthetic Wazuh alerts — no live Wazuh, no Docker, SQLite is created automatically:

```bash
python -m scripts.run_poc [--offline]
.venv/Scripts/python -m uvicorn app.main:app --reload   # http://localhost:8000
```

For a live feed, see **Live Wazuh** below, then set `WAZUH_LIVE_POLLING=true` in `.env` —
`app.main` starts a background poller that runs poll → triage → correlate → stitch on a schedule.

## Live Wazuh (4.9.x)

zuumb does not ship Wazuh; it reads alerts from an existing stack's **indexer**
(`wazuh-alerts-*`, port 9200 — not the Manager API on 55000). This is the exact
flow used to stand one up under WSL Docker and enrol an agent.

> Docker here runs under WSL, so commands are `docker …` inside WSL; ports are
> published to `localhost` on the Windows host.

### 1. Wazuh 4.9.2 single-node stack

```bash
git clone --depth 1 -b v4.9.2 https://github.com/wazuh/wazuh-docker.git ~/wazuh-docker-4.9.2
cd ~/wazuh-docker-4.9.2/single-node

docker compose -f generate-indexer-certs.yml run --rm generator

# fresh indexer volume, owned by the indexer UID — skips a node.lock
# AccessDenied crash loop, and keeps this stack's volumes separate from any
# other wazuh-docker project on the machine (hence COMPOSE_PROJECT_NAME).
docker volume create wazuh49_wazuh-indexer-data
docker run --rm -v wazuh49_wazuh-indexer-data:/data alpine \
  sh -c 'chown -R 1000:1000 /data && chmod -R 770 /data'

COMPOSE_PROJECT_NAME=wazuh49 docker compose up -d

# wait for green
curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health
```

Defaults from this deployment: indexer `admin` / `SecretPassword`, Manager API
`wazuh-wui` / `MyS3cr37P450r.*-`, dashboard on `https://localhost:443`.

### 2. Read-only ingestion user

zuumb should read as a least-privilege user, never `admin`. Create one on the
indexer's OpenSearch security API:

```bash
ADMIN='admin:SecretPassword'
ING_PASS='choose-a-strong-password'

curl -sk -u "$ADMIN" -X PUT "https://localhost:9200/_plugins/_security/api/roles/zuumb_ingest_ro" \
  -H 'Content-Type: application/json' \
  -d '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read","search","indices:admin/mappings/get","indices:monitor/settings/get"]}]}'

curl -sk -u "$ADMIN" -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/zuumb-ingest" \
  -H 'Content-Type: application/json' -d "{\"password\":\"$ING_PASS\"}"

curl -sk -u "$ADMIN" -X PUT "https://localhost:9200/_plugins/_security/api/rolesmapping/zuumb_ingest_ro" \
  -H 'Content-Type: application/json' -d '{"users":["zuumb-ingest"]}'

# verify: read is allowed, write is refused
curl -sk -o /dev/null -w 'read  %{http_code} (want 200)\n' -u "zuumb-ingest:$ING_PASS" \
  "https://localhost:9200/wazuh-alerts-*/_search?size=1"
curl -sk -o /dev/null -w 'write %{http_code} (want 403)\n' -u "zuumb-ingest:$ING_PASS" \
  -X POST "https://localhost:9200/zuumb-probe/_doc" -H 'Content-Type: application/json' -d '{}'
```

### 3. Enrol an agent

Run on whatever host you want telemetry from. Here it is the WSL Ubuntu box itself:

```bash
curl -so /tmp/wazuh-agent.deb \
  https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb

sudo WAZUH_MANAGER='localhost' WAZUH_AGENT_NAME='my-agent' dpkg -i /tmp/wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo /var/ossec/bin/wazuh-control status
```

`WAZUH_MANAGER` + the first service start auto-enrols against the manager's
`authd` on port 1515 (published by the compose stack). Confirm the manager sees it:

```bash
docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

### 4. Confirm alerts are landing

```bash
# make a little noise
for i in 1 2 3; do sudo -k; echo wrongpass | sudo -S true 2>/dev/null; done
sudo cat /etc/shadow > /dev/null

curl -sk -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-alerts-*?v"
```

A `wazuh-alerts-4.x-*` index with a non-zero `docs.count` means the feed is live.

### 5. Point zuumb at it

```ini
# .env
WAZUH_API_URL=https://localhost:9200
WAZUH_API_USER=zuumb-ingest
WAZUH_API_PASSWORD=the-password-you-chose
WAZUH_VERIFY_SSL=false
WAZUH_ALERTS_INDEX=wazuh-alerts-*
WAZUH_LIVE_POLLING=true
WAZUH_POLL_SECONDS=60
```

```bash
.venv/Scripts/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The console logs each cycle (`wazuh poll: ingested=… triaged=…`). The first run
triages the whole backlog in batches of 40 per tick, so incidents and charts
fill in progressively — watch http://localhost:8000.

Postgres (optional, replaces SQLite): `docker compose up -d postgres`, then set `DATABASE_URL` in `.env`.

## Adding Wazuh agents

Attack chains only form when activity spans more than one source, so zuumb wants
several agents reporting. Two ways to add them.

### A. Container agents (the multi-host lab)

There's no `wazuh/wazuh-agent` image for 4.9.x (Docker Hub starts at 4.13), so
`docker/agent/` builds one from the official `.deb`. `docker-compose.agents.yml`
runs two of them.

> Run every `docker compose -f docker-compose.agents.yml …` command **from the
> repo root** (the file is `./docker-compose.agents.yml`). From WSL that's
> `cd /mnt/<drive>/…/zuumb` first. Plain `docker …` commands (below) work from
> anywhere.

```bash
# the Wazuh stack must be up first (it owns the network the agents join)
docker compose -f docker-compose.agents.yml up -d --build
```

- `agent-lab-01`, `agent-lab-02` join the manager's `wazuh49_default` network and
  enrol automatically on first start.
- Each keeps its enrolment key in a volume (`agentNN-etc`). The manager rejects a
  *duplicate agent name*, so an agent must enrol exactly once — the volume lets
  `restart` / recreate reconnect instead of re-enrolling. To force a clean
  re-enrol: `docker compose -f docker-compose.agents.yml down -v`.
- `restart: unless-stopped` — they come back on every Docker / laptop restart
  until you explicitly `docker compose -f docker-compose.agents.yml down`.
- `LAB_NOISE=1` (in the compose file) seeds realistic sshd auth-failure traffic
  with rotating source IPs so the pipeline has data while real traffic builds.
  **Remove `LAB_NOISE` when the agents monitor real hosts** — a real deployment
  watches real activity, it doesn't manufacture it.

**Add a third (Nth) agent** — in `docker-compose.agents.yml`, copy a service
block and add its volume:

```yaml
services:
  agent-lab-03:
    <<: *agent
    hostname: agent-lab-03
    volumes: ["agent03-etc:/var/ossec/etc"]
volumes:
  agent03-etc:
```

then `docker compose -f docker-compose.agents.yml up -d --build`. The `hostname`
becomes the agent name the manager registers.

**Container agent commands** — from the repo root:

```bash
docker compose -f docker-compose.agents.yml ps            # status / health
docker compose -f docker-compose.agents.yml logs -f agent-lab-01
docker compose -f docker-compose.agents.yml restart agent-lab-02
docker compose -f docker-compose.agents.yml down          # stop + remove all
docker compose -f docker-compose.agents.yml build --no-cache   # rebuild the image (e.g. new .deb)
```

…or from anywhere, by container name (`docker ps` to list them):

```bash
docker ps --filter name=zuumb-agents            # the agent containers + health
docker restart zuumb-agents-agent-lab-02-1
docker logs -f zuumb-agents-agent-lab-01-1
```

### B. A real host (bare-metal or VM)

Same steps as **Live Wazuh → 3. Enrol an agent** above — run them on the other
machine. Set `WAZUH_MANAGER` to `localhost` only if that machine runs the stack,
otherwise to the manager host's LAN IP, and give each host a distinct
`WAZUH_AGENT_NAME`. Windows/macOS use the platform installer from
<https://packages.wazuh.com/4.x/> with the same two env vars.

### How many agents are running

```bash
# canonical count — active / disconnected / never_connected / total (excludes the manager itself)
TOKEN=$(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/agents/summary/status"
# -> {"data":{"connection":{"active":3,"disconnected":0,"never_connected":0,"pending":0,"total":3}, ...}}

# quick check without the API token (counts id 000, the manager, too — subtract 1)
docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/agent_control -l | grep -c Active

# just the container agents (from the repo root)
docker compose -f docker-compose.agents.yml ps
```

### Verify an agent

```bash
# manager's view — the agent should read Active, not "Never connected" / Disconnected
docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/agent_control -l

# its alerts are reaching the indexer
curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?size=3&q=agent.name:agent-lab-01&sort=timestamp:desc"
```

If an agent is stuck "Never connected": it enrolled (has a key) but can't reach
the manager on **1514/tcp** — check the address it's using
(`grep '<address>' /var/ossec/etc/ossec.conf` in the agent) and that 1514 is
published by the stack.

If a container agent logs `Duplicate agent name … Unable to add agent`: its key
volume is out of sync with the manager. `docker compose -f docker-compose.agents.yml
down -v` then `up` to re-enrol from scratch.

### Remove an agent

```bash
docker compose -f docker-compose.agents.yml stop agent-lab-02      # container: stop it
docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/manage_agents -r <id>   # id from agent_control -l
```

The stack's `authd` has `<purge>yes</purge>`, so a removed key is cleared from
the manager automatically on the next restart.

### Daily bring-up

After a full shutdown (otherwise everything auto-restarts):

```bash
wsl bash scripts/lab-up.sh     # Wazuh stack -> wait for indexer -> agents -> prints agent list
# then, in the repo:
.venv/Scripts/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Tuning attack chains on real traffic

Let live data accumulate for a few days, then check chain quality:

```bash
python -m scripts.chain_quality
```

It prints, per chain, the entities that join each pair of adjacent stages, and
flags two false-chain shapes:

- **hub-host** — every link is one shared host (a proxy / jump box, not an attack path)
- **weak-link** — adjacent stages share no entity directly (stitched only transitively)

Knobs (both `.env`-overridable):

| var | default | when to change |
|-----|---------|----------------|
| `CORRELATION_WINDOW_MINUTES` | `30` | shrink if noisy traffic over-merges unrelated alerts into one incident |
| `CHAIN_MAX_ENTITY_SPREAD` | `4` | lower if a busy shared host keeps stitching unrelated incidents together |

## Automated mitigation (active response, Phase 14)

Approving a response task can dispatch a real command to the agent via Wazuh's
Active Response API — **but only** from a fixed allowlist, only after a human
clicks Approve, and only if `RESPONSE_DRY_RUN` is off.

| Action | Wazuh script | Needs | Second confirm |
|--------|--------------|-------|----------------|
| `block-ip` | `!firewall-drop` | a source IP + agent id from the incident | no |
| `disable-user` | `!disable-account` | a username + agent id | **yes** |

The `!` prefix runs the hardened agent script directly (no manager
`<active-response>` block needed). Everything else stays a manual task.

**How it flows:** `app/response/playbooks.py` tags a proposed task with an
`action` when the incident yields a target (ip/user) and an agent id →
`app/response/approve.py` on Approve either records intent (dry-run) or calls
`app/response/active_response.py:dispatch()` → `PUT /active-response` with the
`zuumb-ar` credential → a row in `response_actions_log`, shown at `/audit` and
under the incident's "Dispatched actions".

### `RESPONSE_DRY_RUN` — default **on**

With `RESPONSE_DRY_RUN=true` (the default in `.env.example`), Approve marks the
task done and writes a **`response_actions_log`** row recording *what would have
been dispatched* — nothing reaches a host. Every dispatch, dry-run or live, is in
that log; see it at **`/audit`** or under an incident's "Dispatched actions".

Set `RESPONSE_DRY_RUN=false` **only** when you want approvals to run real
commands on real machines. Live dispatches are rate-limited
(`RESPONSE_RATE_LIMIT_SECONDS`, default 30).

### The AR credential

A **separate** least-privilege Manager API user (`:55000`), never the ingestion
one. Wazuh already ships a built-in policy (`agents_commands_agents`) that grants
exactly `active-response:command` — attach it to a fresh role + user:

```bash
API='https://localhost:55000'; H="Authorization: Bearer $(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' -X POST "$API/security/user/authenticate?raw=true")"
id() { python3 -c "import sys,json;print(json.load(sys.stdin)['data']['affected_items'][0]['id'])"; }
AR_PASS='Zuumb.AR.pass1'          # 8+ chars, mixed — and NO '!' (bash history-expands it)

ROLE=$(curl -sk -H "$H" -X POST "$API/security/roles" -H 'Content-Type: application/json' -d '{"name":"zuumb_ar"}' | id)
curl -sk -H "$H" -X POST "$API/security/roles/$ROLE/policies?policy_ids=6" >/dev/null   # 6 = agents_commands_agents
USER=$(curl -sk -H "$H" -X POST "$API/security/users" -H 'Content-Type: application/json' -d "{\"username\":\"zuumb-ar\",\"password\":\"$AR_PASS\"}" | id)
curl -sk -H "$H" -X POST "$API/security/users/$USER/roles?role_ids=$ROLE" >/dev/null

# verify: AR allowed, everything else denied
ART=$(curl -sk -u "zuumb-ar:$AR_PASS" -X POST "$API/security/user/authenticate?raw=true"); sleep 2
curl -sk -o /dev/null -w 'PUT /active-response -> %{http_code} (want 200)\n' -H "Authorization: Bearer $ART" \
  -X PUT "$API/active-response?agents_list=001" -H 'Content-Type: application/json' -d '{"command":"!firewall-drop","arguments":["203.0.113.9"]}'
curl -sk -o /dev/null -w 'DELETE /agents      -> %{http_code} (want 403)\n' -H "Authorization: Bearer $ART" -X DELETE "$API/agents?agents_list=999&status=all&older_than=0s"
```

Then in `.env`: `WAZUH_AR_API_URL`, `WAZUH_AR_API_USER=zuumb-ar`, `WAZUH_AR_API_PASSWORD`.

### Try the flow, end to end

`data/synthetic_alerts/ar_demo.jsonl` builds two incidents on `agent-lab-01`: a
6-alert SSH brute force from `203.0.113.99` → **block-ip** task, and a
useradd+login by `mallory` → **disable-user** task (confirm twice).

> zuumb and its venv are on Windows — run steps **1–7 in PowerShell from the repo
> root** (`.venv\Scripts\python.exe`). Docker is under WSL — the `docker exec`
> checks run **in WSL**. `python -m scripts.run_poc` fails from WSL: wrong
> interpreter, wrong directory.

**1. (only if `agent-lab-01` isn't id `006`)** — check in WSL with
`docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/agent_control -l`, then in PowerShell:
```powershell
$env:AGENT_ID=<id>; .venv\Scripts\python.exe data\synthetic_alerts\gen_ar_demo.py
```

**2. Ingest + correlate** (PowerShell):
```powershell
.venv\Scripts\python.exe -m scripts.run_poc --offline
```

**3. Find the action tasks** (PowerShell):
```powershell
.venv\Scripts\python.exe -c "from app.db.session import get_session; from app.db.models import Task; from sqlmodel import select; s=get_session(); [print('incident',t.incident_id,'task',t.id,'->',t.action,t.action_target,'@',t.agent_id) for t in s.exec(select(Task).where(Task.action!=None)).all()]"
```

**4. Dry-run** — start the app, approve, look at `/audit`:
```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```
In the browser open the incident, click **Approve** on the block-ip task (for
disable-user you'll get a red *Confirm dispatch* — click it again). Or from a
second PowerShell: `curl.exe -s -X POST http://localhost:8000/tasks/<task-id>/approve`.
`/audit` shows the row as `dry-run`; nothing reached the host.

**5. Go live** — stop uvicorn (Ctrl+C), then (PowerShell):
```powershell
(Get-Content .env) -replace 'RESPONSE_DRY_RUN=true','RESPONSE_DRY_RUN=false' | Set-Content .env
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```

**6. Approve the block-ip task again** (browser or `curl.exe` as in step 4).
`/audit` now shows `live · ok · 200`.

**7. Verify on the agent** (WSL):
```bash
docker exec zuumb-agents-agent-lab-01-1 iptables -S | grep 203.0.113.99
docker exec zuumb-agents-agent-lab-01-1 tail -3 /var/ossec/logs/active-responses.log
```
You should see a `-A INPUT -s 203.0.113.99/32 -j DROP` rule and the
`firewall-drop` invocation.

### Revert

```powershell
# PowerShell — back to dry-run, then restart uvicorn
(Get-Content .env) -replace 'RESPONSE_DRY_RUN=false','RESPONSE_DRY_RUN=true' | Set-Content .env
```
```bash
# WSL — the container's iptables isn't persisted; a restart clears the DROP rule
docker compose -f docker-compose.agents.yml restart agent-lab-01
```
The `ar_demo` incidents and the `/audit` rows are harmless history. For a clean
slate: `Remove-Item zuumb.db` (PowerShell) and re-run step 2 — or keep it and
`mv zuumb.db` aside if you want the live data back later.

## Build status
- **Phase 1** scaffold + infra — done (Wazuh external; infra is Postgres-only).
- **Phase 2** ingestion (synthetic alert JSON → DB) — done.
- **Phase 3** triage agent (Claude → structured verdict) — done.
- **Phase 4** POC checkpoint (`scripts/run_poc.py`) — done, demoed with real API.
- **Phase 5** correlation engine (`app/correlation/engine.py`) — done.
- **Phase 6** dashboard v1 (FastAPI + Jinja2) — done.
- **Phase 6b** dashboard viz upgrade (brand theme toggle + Chart.js charts) — done.
- **Phase 6c** Wazuh-parity UI pass (breadcrumb nav, widget chrome, dense grid, severity palette, tight tables) — done.
- **Phase 7** attack chain stitcher (`app/attack_chain/stitcher.py`) + `/chains` view — done.
- **Phase 8** response layer (`app/response/playbooks.py`, propose-only, no execution) — done.
- **Phase 9** feedback loop (`app/feedback/logger.py`, analyst override → few-shot in triage prompt) — done.
- **Phase 10** eval harness (`eval/run_eval.py`, 34-alert labeled set) — done; baseline acc 0.82, +few-shot 0.94 ([eval/RESULTS.md](eval/RESULTS.md)).
- **Phase 12** live Wazuh ingestion (`app/ingestion/wazuh_client.py` poller + `app/pipeline.py`) — done against a live 4.9.2 stack.
- **Phase 13** attack chains at scale — `CHAIN_MAX_ENTITY_SPREAD` knob, `scripts/chain_quality.py` diagnostic, container agent lab (`docker/agent/`, `docker-compose.agents.yml`); validation ongoing against real traffic.
- **Phase 14** human-approved active response — allowlisted Wazuh AR dispatch (`app/response/active_response.py`), approve→dispatch flow with dry-run default + audit log (`app/response/approve.py`, `/audit`); live throwaway-agent test pending.
