# CLAUDE.md — zuumb

Full build plan: [zuumb-buildplan.md](zuumb-buildplan.md). Read it before starting a phase.

## What this is
An AI-Native Detection & Response layer on top of Wazuh: pull alerts → LLM triage
verdict → entity/time correlation into incidents → (MVP) attack chain + response
task proposals + analyst feedback loop → dashboard.

## Working rules (from the plan, Sections 8 & 0)
- Work **phase by phase** (build order in plan Section 7). Don't touch later-phase files.
- Response layer **never executes** anything — propose + human-click-to-mark-done only.
- Triage prompt lives in `prompts/triage_vN.md`, never an inline string.
- All LLM calls must be **mockable** — triage tests run without hitting the API.
- No scale-testing. Docker Compose is the whole infra. No Kafka/k8s/multi-node.
- Secrets in `.env` (gitignored). `.env.example` has placeholders only.
- Default model: `claude-haiku-4-5-20251001`, set via `ANTHROPIC_MODEL` env var.
- After each build step: `/ponytail-review`. Before POC + MVP checkpoints: `/ponytail-audit`.

## Environment notes
- Docker runs under **WSL only** — call it as `wsl.exe -e bash -c '...'`, not `docker` on PATH.
- Wazuh is **external**: a `single-node-*` v5.0.0-beta4 stack is already running (API `wazuh`/`wazuh`
  at https://localhost:55000). This repo does not define Wazuh services.
- POC targets **synthetic alert JSON** (`data/synthetic_alerts/`), not live Wazuh. Live API
  polling is deferred to the MVP (plan step: "real-time-ish polling").

## Layout
- `docker-compose.yml` — Postgres only (MVP; POC uses SQLite)
- `app/` — the AIDR service (config, db, ingestion, triage, correlation, ...)
- `prompts/` — versioned triage prompts
- `data/synthetic_alerts/` — replay/sample alert sets
- `eval/` — labeled set + precision/recall harness

## Quickstart
See [README.md](README.md).
