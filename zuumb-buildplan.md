# zuumb — Build Plan for Claude Code

**Project codename:** zuumb (Wazuh + LLM triage/correlation layer)
**Inspiration:** CipherData AIDR (AI-Native Detection & Response) — triage agent → correlation engine → attack chain → response tasks, human-approved.
**Author context:** Built on top of existing Wazuh detection rule work (Caddy ruleset, 29 rules, merged upstream). This project is the natural next layer: detection engineering → AI-native detection.

---

## 0. How to use this document with Claude Code

Drop this file in the repo root as `CLAUDE.md` (Claude Code auto-reads `CLAUDE.md` at session start for project context) and also keep a copy as `docs/BUILD_PLAN.md`. Then work phase by phase — paste one phase at a time into Claude Code rather than asking it to build everything in one shot. Suggested prompt pattern per phase:

```
Read CLAUDE.md. We are on Phase <N>. Build only what's listed under
Phase <N> scope. Don't touch later-phase files. Write tests for
everything you add. Stop and summarize before moving to the next phase.
```

**A note on timeline:** the phases below are checkpoints, not calendar estimates — Claude Code can plausibly scaffold most of the code in one long session. What actually paces this project isn't code-generation speed, it's: (1) getting the Wazuh Docker stack running and confirming real API responses, which usually needs a debugging pass against the live containers; (2) iterating on the triage prompt against the eval set until precision/recall look reasonable, which is judgment-driven, not generation-driven; and (3) you reviewing each checkpoint before the next phase builds on it. It's reasonable to hand this to Claude Code in one sitting and let it try to build straight through the POC — just expect the MVP's prompt-tuning and eval rounds to still take a few separate passes after that.

**Mandatory skill: `ponytail`.** This project must use the `ponytail` command set throughout the build — it's already installed in this Claude Code setup. Available variants:
- `/ponytail` — base command
- `/ponytail-debt` — technical debt check
- `/ponytail-audit` — audit pass
- `/ponytail-review` — code review pass
- `/ponytail-gain` — (use as appropriate to its function)
- `/ponytail-help` — reference/help

Run the relevant `ponytail` variant at the end of **every phase** in Section 7 before moving on — at minimum `/ponytail-review` after each phase's code is written, and `/ponytail-audit` before the POC and MVP checkpoints (Sections 8/9). Do not skip this step even if the phase feels small.

**Mandatory personas: Agency Agents.** The Core Dev subset of `msitarzewski/agency-agents` (~95 agents — engineering, testing, design, security, product) is already installed at `~/.claude/agents/`. Activate the relevant persona by name before starting each build step rather than prompting Claude Code generically — see the mapping table in Section 7b. Combine with `ponytail`: activate the persona first, have it do the work, then run the appropriate `/ponytail` command on the output before moving to the next step.

---

## 1. Project Goal

Build a small, demoable **AI-Native Detection & Response (AIDR) layer on top of Wazuh** that:

1. Pulls alerts from Wazuh in near-real-time.
2. Runs each alert through an **LLM triage agent** that returns a verdict (benign / suspicious / malicious), confidence, and reasoning.
3. **Correlates** related alerts (shared host/user/IP, time-windowed) into incidents.
4. Optionally chains related incidents into a lightweight **attack narrative** using MITRE ATT&CK stage ordering.
5. Proposes **response actions** (never auto-executes) that a human approves.
6. Logs analyst overrides so the triage prompt improves over time (simple feedback loop, not full fine-tuning for MVP).

Non-goals for POC/MVP: multi-tenant SaaS, auto-remediation, enterprise-scale event throughput, SOC 2 compliance, EDR/cloud connectors beyond Wazuh.

---

## 2. Two-Stage Scope

### PHASE A — POC (proof of concept)
Goal: prove the core loop works end to end on synthetic data. Ugly is fine. No auth, no persistence beyond SQLite, single script or minimal service, CLI or barebones UI acceptable.

**POC must demonstrate:**
- Wazuh alert → LLM verdict (single alert, single call)
- 3–5 related alerts → grouped into 1 incident (basic entity correlation)
- Verdict + grouping displayed somewhere readable (terminal table or simple HTML page)

**POC explicitly excludes:** attack chain stitching, response/playbook layer, feedback loop, auth, real-time streaming (batch/poll is fine), any deployment concerns.

### PHASE B — MVP
Goal: a small but complete lifecycle demo you could show in an interview or portfolio video.

**MVP adds on top of POC:**
- Real-time-ish polling from Wazuh API (not manual batch)
- Correlation engine as a proper module (not a script)
- Lightweight attack chain view (MITRE ATT&CK stage sequencing across incidents)
- Response task proposals (playbook suggestions, human-approve UI action, no execution)
- Analyst verdict override logging → feeds back into next triage prompt as few-shot examples
- Simple web dashboard (incidents list → incident detail → attack chain view → tasks)
- Basic auth (even just a single hardcoded login) so it's demoable without being wide open
- Eval harness: a labeled synthetic alert set + script to measure triage precision/recall

---

## 3. Architecture

```
                    ┌─────────────────────┐
   Wazuh Manager    │   Wazuh Indexer/API   │
 (rules, decoders)  │  (alerts, REST API)   │
                    └──────────┬───────────┘
                               │ poll / webhook
                               ▼
                    ┌─────────────────────┐
                    │   Ingestion Service   │  (Python)
                    │  normalizes alerts    │
                    └──────────┬───────────┘
                               ▼
                    ┌─────────────────────┐
                    │    Triage Agent       │  (LLM call per alert)
                    │  verdict + reasoning  │
                    └──────────┬───────────┘
                               ▼
                    ┌─────────────────────┐
                    │  Correlation Engine   │  (entity + time window)
                    │   alerts → incidents  │
                    └──────────┬───────────┘
                               ▼
                    ┌─────────────────────┐
                    │  Attack Chain Module  │  (MITRE stage ordering)
                    │  incidents → chains   │
                    └──────────┬───────────┘
                               ▼
                    ┌─────────────────────┐
                    │   Response Layer      │  (playbook suggestions)
                    │  human-approve only   │
                    └──────────┬───────────┘
                               ▼
                    ┌─────────────────────┐
                    │   Feedback Logger     │  (analyst overrides)
                    │  → few-shot examples  │
                    └───────────────────────┘

                    ┌─────────────────────┐
                    │   Web Dashboard        │  (reads from DB, all stages)
                    └───────────────────────┘
```

**Data store:** SQLite for POC, Postgres for MVP (schema below works for both).

---

## 4. Tech Stack (requirements.txt equivalent)

### Cost & Setup
- **Wazuh, Docker, Postgres, FastAPI, Atomic Red Team** — all free/open source, no billing needed.
- **Anthropic API key required** — this is the one real cost. Pay-per-token, no subscription. Get a key at platform.claude.com and add it to `.env` as `ANTHROPIC_API_KEY` (never commit it — keep it in `.env.example` as a placeholder only).
- **Model choice:** use **Claude Haiku 4.5** (`claude-haiku-4-5-20251001`) for the triage agent by default. Triage is a classification-style task (verdict + confidence + reasoning), not deep multi-step reasoning, so Haiku is the right cost/quality fit — roughly $1/$5 per million input/output tokens vs Sonnet's higher rate. Reserve Sonnet for anything genuinely harder later (e.g. attack-chain narrative generation), if Haiku's output quality isn't good enough there.
- **Expected POC/MVP cost:** a few dollars total for a batch of a few hundred synthetic alerts — this is not production traffic, so it won't run up a real bill. New Anthropic accounts also start with some free credit that likely covers the whole POC phase.
- Set `ANTHROPIC_MODEL` as an env var (not hardcoded) so swapping models later is a one-line change.

### Backend
```
python>=3.11
fastapi
uvicorn
httpx                 # Wazuh API calls
anthropic             # Claude API for triage agent
sqlmodel              # or sqlalchemy — ORM over SQLite/Postgres
pydantic
python-dotenv
apscheduler           # polling scheduler for MVP
pytest
pytest-asyncio
```

### Frontend (MVP dashboard — pick ONE)
- Option A (fastest): server-rendered HTML with Jinja2 + HTMX (no separate frontend build, plays well with FastAPI, Claude Code builds this fastest)
- Option B: React + Vite + Tailwind if you want it portfolio-polished / deployable as a standalone SPA

### Infra
```
docker
docker-compose         # spins up Wazuh (single-node), the app, Postgres
```

### Wazuh
- Use the official **Wazuh single-node Docker deployment** for local dev (manager + indexer + dashboard). Don't build a multi-node cluster for this.
- Use **Atomic Red Team** or a simple log-replay script to generate synthetic attack traffic for testing (safe, no real attacker infra needed).

### LLM
- Claude via Anthropic API for the triage agent (structured JSON output — verdict, confidence, reasoning, MITRE technique guess).
- Keep the triage prompt in a versioned file (`prompts/triage_v1.md`), not hardcoded in Python — you'll iterate on it a lot and want diffable history.

---

## 5. Data Model (minimum viable schema)

```
alerts
  id, wazuh_alert_id, timestamp, rule_id, rule_description,
  agent_name, src_ip, dst_ip, user, raw_json

verdicts
  id, alert_id (FK), verdict (benign|suspicious|malicious),
  confidence (0-1), reasoning_text, mitre_technique, model_version, created_at

incidents
  id, title, status (open|investigating|closed), severity,
  created_at, closed_at

incident_alerts
  incident_id (FK), alert_id (FK)     # many-to-many

attack_chains
  id, title, created_at

attack_chain_incidents
  attack_chain_id (FK), incident_id (FK), stage_order

tasks
  id, incident_id (FK), type (investigation|mitigation),
  title, status (todo|in_progress|done), priority, assignee

analyst_feedback
  id, verdict_id (FK), analyst_verdict, note, created_at
```

---

## 6. Repo Structure

```
zuumb/
├── CLAUDE.md                     # this doc, or a pointer to docs/BUILD_PLAN.md
├── docker-compose.yml            # wazuh single-node + app + postgres
├── .env.example
├── requirements.txt
├── prompts/
│   └── triage_v1.md
├── app/
│   ├── main.py                   # FastAPI entrypoint
│   ├── config.py
│   ├── db/
│   │   ├── models.py
│   │   └── session.py
│   ├── ingestion/
│   │   └── wazuh_client.py       # polls Wazuh API, normalizes alerts
│   ├── triage/
│   │   └── agent.py              # calls Claude, parses structured verdict
│   ├── correlation/
│   │   └── engine.py             # entity/time-window grouping
│   ├── attack_chain/
│   │   └── stitcher.py           # MITRE stage sequencing (MVP only)
│   ├── response/
│   │   └── playbooks.py          # static playbook templates + suggestion logic
│   ├── feedback/
│   │   └── logger.py
│   └── web/
│       ├── routes.py
│       └── templates/            # Jinja2/HTMX or React build output
├── data/
│   └── synthetic_alerts/         # sample/replay alert sets for testing
├── eval/
│   ├── labeled_set.jsonl         # hand-labeled alerts for precision/recall
│   └── run_eval.py
└── tests/
    ├── test_triage.py
    ├── test_correlation.py
    └── test_ingestion.py
```

---

## 7. Build Order (what to tell Claude Code, in sequence)

1. **Scaffold repo** — folder structure above, `requirements.txt`, `.env.example`, `docker-compose.yml` with Wazuh single-node + Postgres. Get `docker-compose up` producing a running Wazuh you can hit via API. *Persona: Backend Architect.*
2. **Ingestion** — `wazuh_client.py`: authenticate to Wazuh API, pull recent alerts, normalize into the `alerts` schema, write to DB. Test against Wazuh's sample/demo alerts first. *Persona: Backend Architect.*
3. **Triage agent** — `agent.py`: take one alert, build prompt from `prompts/triage_v1.md`, call Claude with structured JSON output (use tool calling or strict JSON mode), parse into `verdicts` table. Write unit tests with mocked LLM responses so tests don't burn API calls. *Persona: Backend Architect, then QA/Test Engineer for the mocked tests.*
4. **POC checkpoint** — wire ingestion → triage into a CLI script (`scripts/run_poc.py`) that processes N alerts and prints a table. Run `/ponytail-audit` here before moving on. **Stop here and demo before continuing.** *Persona: Reality Checker for the audit pass.*
5. **Correlation engine** — `engine.py`: group alerts sharing host/user/IP within a configurable time window (e.g. 30 min) into `incidents`. Pure logic, unit-testable without any LLM calls. *Persona: Backend Architect.*
6. **Dashboard v1** — FastAPI + Jinja2/HTMX pages: incidents list, incident detail (shows constituent alerts + verdicts). *Persona: Frontend Developer.*
7. **Attack chain stitcher** — `stitcher.py`: sequence incidents sharing entities by MITRE ATT&CK tactic order (recon → initial access → execution → persistence → ... → exfiltration) into a chain. Keep this simple — ordering + shared-entity grouping, not a real graph ML model. *Persona: Backend Architect.*
8. **Response layer** — `playbooks.py`: static templates keyed by MITRE technique or rule category (e.g. "isolate host," "rotate credential," "block IP"), suggested per incident, with an "approve" button that just marks the task done (no real execution — that's a hard line for a portfolio project, don't cross it). *Persona: Security Engineer to review the guardrail is actually enforced, not just prompted for.*
9. **Feedback loop** — `logger.py`: when an analyst overrides a verdict in the UI, store it in `analyst_feedback`. Modify `agent.py` to pull the last K overrides as few-shot examples in the triage prompt. *Persona: Backend Architect.*
10. **Eval harness** — hand-label 30–50 synthetic alerts (mix of true benign/malicious), run `run_eval.py` to compute precision/recall/confusion matrix for the triage agent. This is your most defensible "proof it works" artifact. *Persona: QA/Test Engineer.*
11. **Polish for demo** — seed with Atomic Red Team-generated attack traffic, record a short walkthrough, write the README with architecture diagram and metrics from the eval harness. Run `/ponytail-audit` as a final pass before calling the MVP done. *Persona: Product (for the README framing/scope check) + Reality Checker (final audit).*

> Reminder: after every numbered step above, activate the listed persona first, then run `/ponytail-review` on the code just written before moving to the next step.

---

## 7b. Agency Agents persona map

| Build area | Persona to activate | Why |
|---|---|---|
| Ingestion, correlation, attack chain, feedback loop (pure backend logic) | **Backend Architect** | Core service and data-layer work, no UI |
| Dashboard (Section 7, step 6) | **Frontend Developer** | HTML/HTMX or React UI work |
| Response layer guardrail (step 8) | **Security Engineer** | Needs to actually verify no execution path exists, not just take the prompt's word for it |
| Unit tests, eval harness (steps 3, 10) | **QA/Test Engineer** | Mocked LLM tests, precision/recall scoring |
| POC/MVP checkpoints, final polish (steps 4, 11) | **Reality Checker** | Pairs naturally with `/ponytail-audit` — both exist to catch "looks done but isn't" |
| Scope decisions, README framing, non-goals boundary | **Product** | Keeps POC/MVP scope honest against Section 1's non-goals list |

Sample prompt pattern combining both tools:
```
Activate Backend Architect. Read CLAUDE.md Section 7, step 5. Build the
correlation engine as specified. When done, run /ponytail-review on it.
```

---

## 8. Guardrails to give Claude Code explicitly

- **Never wire the response layer to actually execute anything** (no real firewall/EDR API calls) — keep it "propose + human click to mark done." This is a safety and scope boundary, not just a nice-to-have.
- **Version the triage prompt as a file, not inline string** — you'll iterate on it constantly.
- **Keep LLM calls mockable** — all triage tests should run without hitting the real API.
- **Don't scale-test.** This is a portfolio/demo project. Resist any urge (yours or Claude Code's) to add Kafka, multi-node anything, or Kubernetes. Docker Compose is enough.
- **Secrets in `.env`, never committed.** `.env.example` with placeholder keys only.

---

## 9. Success Criteria

**POC is done when:** you can run one script, feed it a batch of synthetic Wazuh alerts, and get back a printed table of verdicts + at least one correctly grouped incident.

**MVP is done when:** you can start `docker-compose up`, replay an Atomic Red Team scenario into Wazuh, watch alerts flow through triage → correlation → attack chain → task suggestions in the dashboard, override one verdict, and show the eval harness numbers.

---

## 10. Ponytail usage summary

| When | Command |
|---|---|
| After each build step in Section 7 | `/ponytail-review` |
| POC checkpoint (end of step 4) | `/ponytail-audit` |
| MVP done (end of step 11) | `/ponytail-audit` |
| If technical debt is piling up mid-build | `/ponytail-debt` |
| Unsure which variant fits | `/ponytail-help` |
