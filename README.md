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

### In plain English

zuumb reads Wazuh alerts, groups them into **incidents**, and for each incident
suggests **response tasks** — short instructions like "block that IP" or "lock
that account". Until Phase 14 those were just notes for a person to act on by
hand. Now a person can **click one button** and have zuumb carry the task out on
the affected machine — by asking Wazuh to do it, never by running commands
itself.

Three things are always true:

- Nothing happens on its own — a human clicks **Approve** first.
- zuumb can only do a few **specific** things (see the table below), never "run
  any command".
- Out of the box it runs in **practice mode** (`RESPONSE_DRY_RUN=true`): the
  button works, writes a record, and touches nothing.

### Words used here

| Term | Plain meaning |
|------|---------------|
| **Wazuh manager** | The central Wazuh server. zuumb talks to it over HTTPS on port `55000`. |
| **Wazuh agent** | A small program on a machine you want to protect. Each has a numeric **agent id** — `001`, `006`, and so on. |
| **Active Response (AR)** | A built-in Wazuh feature: the manager tells an agent to run a small, pre-installed script (block an IP, lock an account, …). |
| **AR script** | The pre-installed program the agent runs — e.g. `firewall-drop` (adds a firewall rule) or `disable-account` (locks a local user). |
| **Dispatch** | zuumb sending one "run this AR script on this agent" request to the manager. |
| **Allowlist** | The short, fixed list of actions zuumb is permitted to dispatch. Anything not on it is impossible. |
| **Dry-run** | Practice mode. Approving records *what would have happened* and stops. |
| **Audit log** | A table (`response_actions_log`) with one row per Approve click: what, where, who, when, result. Shown at `/audit`. |
| **`zuumb-ar`** | A dedicated Wazuh login zuumb uses **only** to dispatch AR. It can do that and nothing else. |
| **iptables DROP rule** | A Linux firewall entry that silently discards traffic from an IP. `firewall-drop` adds one. |
| **RBAC** | "Role-Based Access Control" — Wazuh's way of saying "this login may do X but not Y". |
| **PowerShell / WSL** | zuumb runs on Windows → **PowerShell**. Docker + Wazuh run under **WSL** (Linux). Commands below say which to use. |

### The safety rules, and why each one exists

| Rule | Why |
|------|-----|
| Only actions on a fixed allowlist | A bug or a bad LLM response can never turn into an arbitrary command. |
| A human clicks **Approve** | zuumb proposes; a person decides. No auto-fire. |
| **Dry-run is the default** | You can test the whole flow without touching a real machine. |
| A **separate least-privilege login** (`zuumb-ar`) | If that credential leaks it can *only* dispatch AR — not read alerts, delete agents, or change settings. |
| **Every** Approve is logged (dry-run and live) | There is always a record of what was, or would have been, done. |
| `disable-user` needs a **second confirm** | Locking an account can lock out a real person; one stray click shouldn't. |
| Live dispatches are **rate-limited** (30 s default) | A double-click or a loop can't fire a burst of real actions. |

### What happens when you click Approve

```text
 Wazuh agent  --alerts-->  zuumb poller  --score-->  incident + response tasks
                                                              |
                                    a task gets TAGGED with:  action + target + agent id
                                    e.g.  block-ip / 198.51.100.77 / 006
                                                              |
                                          you click  "Approve"  in the dashboard
                                                              |
                                             is RESPONSE_DRY_RUN true?
                        +---------------- YES ----------------+------------- NO -------------+
                        |                                    |                             |
              write an audit row                     check the 30 s rate limit
              marked "dry-run",                              |
              dispatch NOTHING                       POST /active-response
                        |                            (logs in as zuumb-ar)
                        |                                    |
                        |                            Wazuh manager --> agent
                        |                                    |
                        |                            agent runs firewall-drop
                        |                                    |
                        |                            real iptables DROP rule added
                        |                                    |
                        |                            write an audit row
                        |                            marked "live" + the result
                        +------------------+-----------------+
                                           |
                             row shows at  /audit  and on the incident page
```

Which file does what:

```text
app/response/playbooks.py       proposes tasks; tags the ones that map to an action
app/response/approve.py         on Approve: dry-run log  OR  call dispatch(), then log
app/response/active_response.py  dispatch(): the ONLY code that calls the Wazuh AR API
app/db/models.py                ResponseActionLog  = the audit table
app/web/routes.py               POST /tasks/<id>/approve   and   GET /audit
```

### The two actions zuumb can take

| Action | What it does | Wazuh script | Needs from the incident | Second confirm? |
|--------|--------------|--------------|-------------------------|-----------------|
| `block-ip` | Firewall-drops an attacker's source IP on the affected host | `!firewall-drop` | a source IP **and** the agent id | no |
| `disable-user` | Locks a compromised local account on the affected host | `!disable-account` | a username **and** the agent id | **yes** |

The `!` prefix tells Wazuh "run this named script directly". Any other response
task stays a manual to-do — zuumb will not dispatch it.

---

### Step 1 — create the `zuumb-ar` login (once)

Run **in WSL** — this talks to the Wazuh manager. Line by line:

```bash
API='https://localhost:55000'
# log in as the manager admin (default for the 4.9.2 docker stack) and keep the token
H="Authorization: Bearer $(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' -X POST "$API/security/user/authenticate?raw=true")"
# helper: pull the numeric id out of a Wazuh JSON reply
id() { python3 -c "import sys,json;print(json.load(sys.stdin)['data']['affected_items'][0]['id'])"; }
# password: 8+ chars, upper+lower+digit+symbol, and NO '!' (bash mangles '!')
AR_PASS='Zuumb.AR.pass1'

# 1) make an empty role called "zuumb_ar"
ROLE=$(curl -sk -H "$H" -X POST "$API/security/roles" -H 'Content-Type: application/json' -d '{"name":"zuumb_ar"}' | id)
# 2) attach Wazuh's built-in policy #6 = "may run active-response commands", nothing else
curl -sk -H "$H" -X POST "$API/security/roles/$ROLE/policies?policy_ids=6" >/dev/null
# 3) create the user "zuumb-ar"
USER=$(curl -sk -H "$H" -X POST "$API/security/users" -H 'Content-Type: application/json' -d "{\"username\":\"zuumb-ar\",\"password\":\"$AR_PASS\"}" | id)
# 4) give the user the role
curl -sk -H "$H" -X POST "$API/security/users/$USER/roles?role_ids=$ROLE" >/dev/null

# --- prove the login is correctly limited ---
ART=$(curl -sk -u "zuumb-ar:$AR_PASS" -X POST "$API/security/user/authenticate?raw=true"); sleep 2
curl -sk -o /dev/null -w 'dispatch AR  -> %{http_code}  (want 200 = allowed)\n' -H "Authorization: Bearer $ART" \
  -X PUT "$API/active-response?agents_list=001" -H 'Content-Type: application/json' -d '{"command":"!firewall-drop","arguments":["203.0.113.9"]}'
curl -sk -o /dev/null -w 'delete agent -> %{http_code}  (want 403 = blocked)\n' -H "Authorization: Bearer $ART" \
  -X DELETE "$API/agents?agents_list=999&status=all&older_than=0s"
```

`200` then `403` = success: `zuumb-ar` may dispatch active response and nothing else.

### Step 2 — tell zuumb about it

In `.env` (Windows, repo root):

```ini
WAZUH_AR_API_URL=https://localhost:55000
WAZUH_AR_API_USER=zuumb-ar
WAZUH_AR_API_PASSWORD=Zuumb.AR.pass1
RESPONSE_DRY_RUN=true            # leave true until you deliberately go live
RESPONSE_RATE_LIMIT_SECONDS=30
```

### Step 3 — watch it work, safely (dry-run)

> **PowerShell** = zuumb commands, run from `D:\ai-soc-xdr` with
> `.venv\Scripts\python.exe`. **WSL** = the `docker exec ...` checks. A zuumb
> command in WSL fails with `No module named 'scripts'`.

**3a. (recommended) start from an empty database** — PowerShell, uvicorn stopped:
```powershell
Rename-Item zuumb.db zuumb.db.bak     # keeps your live data aside; you restore it in step 5
```
*Why:* on a busy database the demo alerts merge into existing incidents and the
example targets get replaced by real ones. A fresh DB keeps the walkthrough clean.

**3b. load the sample alerts** — PowerShell:
```powershell
.venv\Scripts\python.exe -m scripts.run_poc --offline
```
*What it does:* reads the sample alert files in `data\synthetic_alerts\`, scores
them (`--offline` = a keyword scorer, no paid LLM), groups them into incidents,
and proposes response tasks. `data\synthetic_alerts\ar_demo.jsonl` is built to
produce one `block-ip` task and one `disable-user` task on `agent-lab-01`.

**3c. list the tasks zuumb tagged as dispatchable** — PowerShell:
```powershell
.venv\Scripts\python.exe -c "from app.db.session import get_session; from app.db.models import Task; from sqlmodel import select; s=get_session(); [print(f'incident {t.incident_id}  task {t.id}  ->  {t.action}  {t.action_target}  on agent {t.agent_id}') for t in s.exec(select(Task).where(Task.action!=None)).all()]"
```
*What it does:* prints every one-click action task. Note the `task <N>` number of
a `block-ip` line whose agent id is a **real** agent (list them in WSL with
`docker exec wazuh49-wazuh.manager-1 /var/ossec/bin/agent_control -l`).

**3d. start zuumb** — PowerShell:
```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```
Open `http://localhost:8000`.

**3e. approve — in the browser:**
1. Incidents list → click the incident.
2. Scroll to **Response tasks**. The dispatchable one shows a tag like
   `⚡ block-ip → 198.51.100.77 · agent 006` and a yellow **DRY-RUN** badge.
3. Click **Approve**.
   - `block-ip` → done at once.
   - `disable-user` → the button turns red and says **Confirm dispatch**; click it
     again to go through (this is the "second confirm" safety rule).

*What just happened:* `RESPONSE_DRY_RUN=true`, so zuumb wrote an audit row saying
"would have run `block-ip` on agent 006" and stopped. Nothing was sent anywhere.

**3f. check the record — in the browser:**

| Look at | You should see |
|---------|----------------|
| top nav → **Audit** (`/audit`) | one row, **MODE = dry-run**, **RESULT = ok** |
| the incident page → **Dispatched actions** | the same row |

### Step 4 — do it for real (live)

> ⚠️ This runs a real firewall command on the target agent. Use a **throwaway**
> agent (`agent-lab-01` / `agent-lab-02` from `docker-compose.agents.yml`), never
> a machine you care about.

**4a. flip the switch** — PowerShell (stop uvicorn with Ctrl+C first):
```powershell
(Get-Content .env) -replace 'RESPONSE_DRY_RUN=true','RESPONSE_DRY_RUN=false' | Set-Content .env
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```
*What it does:* `RESPONSE_DRY_RUN=false` means Approve now really dispatches.

**4b. approve the same `block-ip` task again** — browser, or PowerShell:
```powershell
curl.exe -s -X POST http://localhost:8000/tasks/<TASK-NUMBER>/approve
```
Put the number from step 3c where `<TASK-NUMBER>` is (e.g. `194`).
*Check in the UI:* `/audit` — the newest row now says **MODE = live**,
**RESULT = ok · 200**.

**4c. confirm it actually happened** — WSL (use **your** task's target IP):
```bash
docker exec zuumb-agents-agent-lab-01-1 iptables -S | grep 198.51.100.77
docker exec zuumb-agents-agent-lab-01-1 tail -3 /var/ossec/logs/active-responses.log
```
Expected:
```text
-A INPUT   -s 198.51.100.77/32 -j DROP        <- the firewall now blocks that IP
-A FORWARD -s 198.51.100.77/32 -j DROP
...
active-response/bin/firewall-drop: ... "extra_args":["198.51.100.77"] ...
active-response/bin/firewall-drop: Ended
```
The `-j DROP` line is the whole point: on your click, zuumb had Wazuh block a
real IP on a real host.

### Step 5 — put everything back

**5a. back to practice mode** — PowerShell (Ctrl+C uvicorn):
```powershell
(Get-Content .env) -replace 'RESPONSE_DRY_RUN=false','RESPONSE_DRY_RUN=true' | Set-Content .env
```

**5b. remove the firewall rule** — WSL (your target IP):
```bash
docker exec zuumb-agents-agent-lab-01-1 sh -c \
  'iptables -D INPUT -s 198.51.100.77/32 -j DROP; iptables -D FORWARD -s 198.51.100.77/32 -j DROP; \
   iptables -S | grep 198.51.100.77 || echo cleared'
```
*Or* `docker compose -f docker-compose.agents.yml restart agent-lab-01` — the
container's firewall rules aren't saved, so a restart wipes them.

**5c. restore your real database** (if you renamed it in 3a) — PowerShell:
```powershell
Remove-Item zuumb.db; Rename-Item zuumb.db.bak zuumb.db
```

**5d. restart zuumb** — PowerShell:
```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```
It's back in dry-run. The `/audit` rows stay — that history is intentional.

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
