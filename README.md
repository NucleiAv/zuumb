# zuumb

An AI-Native Detection & Response (AIDR) layer on top of [Wazuh](https://wazuh.com):
Wazuh alert → LLM triage verdict → entity/time correlation into incidents →
(MVP) attack chain, response-task proposals, analyst feedback loop, dashboard.

Built as the next layer on top of prior Wazuh detection-rule work. See
[ai-soc-xdr-buildplan.md](ai-soc-xdr-buildplan.md) for the full plan.

## Prerequisites
- Python 3.11+
- An Anthropic API key ([platform.claude.com](https://platform.claude.com)) — the only paid dependency
- (MVP only) Docker for Postgres, and a Wazuh single-node stack for live polling

## Setup

```bash
cp .env.example .env          # then put your ANTHROPIC_API_KEY in .env

python -m venv .venv
. .venv/Scripts/activate       # Windows;  ".venv/bin/activate" on macOS/Linux
pip install -r requirements.txt
```

## POC (Phases 2–4)

Runs entirely on synthetic Wazuh alert JSON in `data/synthetic_alerts/` — no
live Wazuh, no Docker needed. SQLite is created automatically.

```bash
python -m scripts.run_poc        # (added in Phase 4)
```

## Wazuh (MVP live polling)

This project does not run its own Wazuh. It expects an existing single-node stack.
On this machine one is already running via **WSL Docker** (`single-node-*`,
v5.0.0-beta4), reachable from Windows at:

| Service         | URL                     | Credentials          |
|-----------------|-------------------------|----------------------|
| Wazuh API       | https://localhost:55000 | `wazuh` / `wazuh`    |
| Wazuh indexer   | https://localhost:9200  | `admin` / `SecretPassword` |
| Wazuh dashboard | https://localhost:443   | `admin` / `SecretPassword` |

If you don't have one: `git clone https://github.com/wazuh/wazuh-docker`.

Postgres (MVP): `docker compose up -d postgres`, then set `DATABASE_URL` in `.env`.

## Dashboard (Phase 6)

```bash
D:/ai-soc-xdr/.venv/Scripts/python.exe -m uvicorn app.main:app --reload
```
Then open http://localhost:8000 — incidents list → incident detail (alerts + verdicts).
Populate it first with `python -m scripts.run_poc [--offline]`.

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
