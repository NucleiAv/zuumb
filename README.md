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
