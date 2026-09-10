# zuumb Detection Track — Autonomous ML/DL Detection Engines

A new, separate track from `ai-soc-xdr-buildplan.md`. That document covers zuumb's
core triage/correlation/response layer. This document covers adding real machine
learning detection capability underneath it, so zuumb doesn't just triage alerts
Wazuh already made, it can also generate its own alerts from raw telemetry.

**This track does not replace or block the core buildplan.** It can run in
parallel with Section 11/12 (live Wazuh, real response, remediation) or start
after. The one rule that carries over unchanged: detection can be autonomous,
response stays human-approved, no exceptions, covered in Section 2 below.

---

## 0. Corrections and verification notes on the source material

Before building anything, notes on what was pasted in — two corrections, one confirmation:

1. **SecureBERT has a newer version.** The original SecureBERT (2022, Aghaei et al.,
   Carnegie Mellon/UNC Charlotte) is real and was a legitimate pioneering
   cybersecurity-domain language model, ranked in the top ~100 most-downloaded
   models on Hugging Face by December 2023. But as of late 2025 there is now
   **SecureBERT 2.0**, built on the newer ModernBERT architecture, released with
   Cisco's involvement, with materially better performance on long documents
   (threat intel reports, incident narratives) that the original struggled with.
   Use SecureBERT 2.0 where the plan below calls for a security-domain BERT
   model, not the 2022 original, unless a specific reason favors the older one.
2. **Slips confirmed as described.** `stratosphereips/StratosphereLinuxIPS`
   is a real, actively maintained (releases through mid-2025), free/open
   behavioral ML-based IDS/IPS from Stratosphere Laboratory at Czech Technical
   University in Prague. The description in the source material (modular,
   Zeek/Suricata/Argus input, threat intel lookups, federated learning support)
   matches its actual current README. Safe to build on as described.
3. Everything else referenced (Kitsune, PyOD, River, nfstream, Drain3,
   deep-loglizer, Adversarial Robustness Toolbox, the standard datasets) are
   real, established tools/datasets in active security-ML research use. Confirm
   exact license terms per-tool before any commercial use, most are MIT/BSD/
   Apache/LGPL, fine for a portfolio project as-is.

---

## 0.5. Integration mechanics, decided before D1 starts

Raised during review: "emit an alert in the exact same schema" is the critical
constraint the whole architecture depends on, but it needs to be nailed down
in writing before any code, not improvised mid-phase. Four decisions, made now:

**1. Exact alert shape a detector must produce.** Checked against the real
`normalize_alert`, not assumed. It **hard-requires four fields** and raises
`KeyError` without any of them: `id`, `timestamp`, `rule.id`,
`rule.description`. It reads **five more if present and tolerates their
absence**: `agent.name`, `data.srcip`, `data.dstip`, one of `data.srcuser` /
`data.dstuser` / `data.user`, and `rule.mitre.id`. `rule.level` is **not** a
normalized column, it only ever lives inside the stored verbatim `raw_json`,
but the triage prompt and the alert-detail view both read it back out of
there, so every detector must still set it. Net: a detector synthesizes the
whole dict, `id` + `timestamp` + `rule.{id,description,level}` + `agent.name` +
whatever `data.*` it genuinely has, never a partial dict.

**1a. The `id` field is the dedupe key, mint it so it cannot collide and is
stable per anomaly.** `ingest_alerts` dedupes on `wazuh_alert_id`, which is
`str(raw["id"])`. Real Wazuh ids are `<epoch>.<counter>` (e.g.
`1719412800.123456`). Each detector mints ids as `ml-d<N>-<short-hash>`, where
`<N>` is the phase number and `<short-hash>` hashes the anomaly's defining
features: host + template set + window bounds. No wall-clock component, on
purpose, the same anomaly re-derived a few seconds later in a re-run must hash
to the *same* id or step 6's idempotency check fails. That gives both
properties at once: an ML id can never look like a Wazuh id or another
detector's id, and a repeat detection of the same anomaly produces the same
id, so `ingest_alerts` dedupe absorbs it exactly as it does a re-fetched Wazuh
alert. The reserved numeric ranges in point 2 below are for `rule.id` (what
fired); this scheme is for `id` (which event), separate fields, both matter.

**2. Reserved `rule.id` range for ML-sourced alerts.** Fixed now, while there's
one detector and zero stored data, because backfilling a range convention after
alerts already exist means migrating every stored row plus anything that came
to depend on it (dashboard filters, the chain stitcher, queries isolating
ML-sourced alerts). The convention: **D1 owns `900001`–`900999`. Each later
detector claims the next free 1000-wide block (`901001`–`901999`, and so on)
when it is actually built** — not reserved in advance for detectors that don't
exist yet. `900001`+ is well clear of Wazuh's built-in and custom rule-id
space, and inside Wazuh's 6-digit `rule.id` limit.

**3. Hand-off mechanism from detector to zuumb.** Use a thin ingest path that
reuses the existing dedupe/normalize logic already built for the Wazuh path
(call `ingest_alerts([...])` directly), not JSON-file polling and not a new
HTTP endpoint. This keeps ML-sourced alerts under the exact same correctness
guarantees (idempotency, dedupe) the Wazuh path already has, instead of
building and maintaining a second, parallel set of guarantees.

Two consequences of reusing that path, both fine, both worth stating so they
aren't discovered mid-phase:

- **The existing pipeline cycle picks ML alerts up on its own.** `ingest_alerts`
  only stores. Triage and correlation run on the next `run_pipeline_cycle` tick
  (`triage_pending` + `correlate` + `stitch`), which already selects every
  untriaged alert regardless of where it came from. With `WAZUH_LIVE_POLLING=true`
  that tick fires on schedule and the ML alert flows through with zero extra
  wiring; with live polling off, the detector run (or an operator) has to kick a
  cycle after ingesting.
- **SQLite is single-writer.** The detector is a separate process writing the
  same SQLite file as `uvicorn`. Its `ingest_alerts` call retries on
  `OperationalError: database is locked` (short backoff, a few attempts), or is
  scheduled on an offset from the poller so they rarely write together. This is a
  SQLite property, not a design flaw, and it disappears if the DB ever moves to
  Postgres.

**4. Process boundary.** Every detector runs as its own separate process or
scheduled job, never inside the `uvicorn` web process. Training or scoring
must never be able to block the dashboard or the API.

---

## 1. The core design decision, restated plainly

Don't bolt ML detection into the middle of zuumb's existing pipeline. Add
detectors **in front of** zuumb, each one emitting alerts in the same shape
Wazuh alerts already arrive in. zuumb's existing triage/correlation/chain/
response layer treats every source identically, it never needs to know or
care whether an alert came from a Wazuh rule or a machine learning model.

```
   RAW TELEMETRY
   ├─ Wazuh agent logs / FIM / syscalls
   ├─ network flows (via nfstream, fed from Zeek/Suricata)
   └─ auth logs, process events

            │
            ▼
   DETECTION ENGINES  (pluggable, each independent, each testable alone)
   ├─ Wazuh rules              (signatures, unchanged, today)        ─┐
   ├─ ML anomaly detector A    (auth-log sequence anomalies)         │  each
   ├─ ML anomaly detector B    (network flow anomalies)              │  emits
   └─ (later) supervised model (trained on YOUR analyst corrections) ─┘  an
                                                                          alert
            │                                                         in the
            ▼                                                        SAME
   ┌──────────────────  zuumb (unchanged) ─────────────────────┐      shape
   │  LLM triage: verdict + confidence + reason + MITRE guess  │
   │  correlation: alerts → incidents                          │
   │  attack chains, response task proposals                   │
   │  analyst feedback loop                                    │
   └─────────────────────────────────────────────────────────┘
            │
            ▼
   analyst dashboard → human clicks Approve → response   (unchanged, human-gated)
```

This is also just how real XDR platforms are actually built, many detection
engines, one shared event schema, one correlation/response layer on top.
Nothing novel about the shape, the novelty is doing it as a solo portfolio
project with free tools.

---

## 2. The one guardrail that does not move

**Detection can be fully autonomous. Response cannot.** This isn't a new rule,
it's the same rule already in the core buildplan (Section 8's original
guardrail, carried through Section 11/12), restated here because it's the
single most important sentence in this whole document:

- A detection engine (rule-based or ML-based) scoring/flagging something on its
  own, with no human in the loop, is completely normal, every IDS in existence
  works this way, Wazuh's own rules already do this today.
- A response action (blocking an IP, disabling an account, isolating a host)
  changing something in the real world always requires the existing
  human-click-Approve gate, the existing dry-run default, and the existing
  audit log from Phase 14/Section 12. Adding new, autonomous detection sources
  does not touch this gate in any way, more detectors just means more things
  that might eventually need a human's approval, not more things that act
  without one.

---

## 3. Reference: tools, verified

*Persona: Backend Architect for evaluating fit, Security Engineer for anything touching raw traffic capture.*

| Tool | What it actually is | Fit for zuumb | License note |
|---|---|---|---|
| **Slips** (`stratosphereips/StratosphereLinuxIPS`) | Full standalone ML-based IDS/IPS, detects C2, scans, brute-force, exfiltration from behavioral analysis of Zeek/Suricata/Argus flows | Run alongside, ingest its alert output as a new source, closest thing to "an ML IDS you just run" rather than build | GPL-2.0, confirm before any commercial use, fine for a portfolio |
| **Kitsune / KitNET** (`ymirsky/Kitsune-py`) | Lightweight unsupervised network anomaly detector, an ensemble of small autoencoders learning "normal" traffic online, flags deviations | Wrap as one detector engine, CPU-friendly, self-contained, research-grade code (not production-polished) | Academic/research license, check repo directly before commercial use |
| **PyOD** (`yzhao062/pyod`) | The standard Python anomaly-detection library, Isolation Forest, AutoEncoder, ECOD, COPOD, LOF, and more, not security-specific, you supply features | Build a detector on auth-log or flow features fairly quickly, actively maintained, best starting point for a first custom detector | BSD |
| **River** (`online-ml/river`) | Online/streaming ML library, models that learn continuously from a live event stream rather than a fixed training set | Matches an always-on IDS well, a model that adapts as traffic evolves rather than going stale | BSD |
| **nfstream** (`nfstream/nfstream`) | Turns pcap or live traffic into labeled per-connection flow features | The feature extractor feeding any network ML detector | LGPL |
| **Drain3** (`logpai/Drain3`) | Log parser, turns messy free-text log lines into a small set of reusable templates | Prerequisite for any log-anomaly ML, turns unstructured text into countable structure | MIT |
| **deep-loglizer / loglizer** (`logpai/*`) | Reference implementations of log-anomaly detection (DeepLog-style LSTM, PCA, invariant mining), flags abnormal sequences of log events | Direct host-IDS use, feed it Wazuh archive logs or auth logs | Various open licenses, check per-repo |
| **Adversarial Robustness Toolbox** (`Trusted-AI/adversarial-robustness-toolbox`) | Tests whether an attacker can fool a trained model with crafted input | Use once any detector is trained, addresses the real failure mode "adversaries adapt to your detector" | MIT |
| **SecureBERT 2.0** (`ehsanaghaei/SecureBERT_Plus` or successor per the org's Hugging Face page) | Domain-specific cybersecurity language model, ModernBERT-based, better than the 2022 original on long documents | A fast, cheap second-opinion classifier on alert text, running alongside the Claude-based triage, not instead of it | Check current Hugging Face model card, verify license at time of use since this is a fast-moving release |

## 4. Reference: datasets, by use case

| Domain | Dataset | Notes |
|---|---|---|
| Network flows | UNSW-NB15, CIC-IDS2017 / CSE-CIC-IDS2018 | The standard labeled NIDS benchmark datasets, known label-quality quirks, still the field's reference point |
| Network / botnet C2 | CTU-13, other Stratosphere datasets | Real captured botnet traffic, strong fit for C2 detection specifically |
| Host syscalls | ADFA-LD / ADFA-WD | Classic host-IDS syscall-trace datasets |
| Host auth + process, real enterprise data | LANL Comprehensive Cyber Security Events, Unified Host and Network Data Set | Real logs with labeled red-team activity, strong fit for auth-anomaly detection |
| Host telemetry + APT | DARPA OpTC, DARPA Transparent Computing | Large, labeled APT campaign data in rich host telemetry |
| Log-sequence anomaly | Loghub (`logpai/loghub`, HDFS/BGL/Thunderbird) | For DeepLog/LogBERT-style sequence models |
| Windows/Sysmon, ATT&CK-labeled | OTRF Security-Datasets (Mordor), EVTX-ATTACK-SAMPLES | Labeled Windows events mapped to MITRE ATT&CK, also useful for testing zuumb's existing chain logic end to end |
| Zeek + ATT&CK labels | UWF-ZeekData22 | Confirmed real, peer-published dataset, newer, Zeek-format, tactic-labeled |
| **Avoid as a primary dataset** | NSL-KDD / KDD'99 | 1999-era traffic, fine as a first tutorial exercise, not representative of anything worth deploying |

Datasets are generally research-use with attribution requirements, read each one's actual terms before any commercial use, fine as-is for a portfolio project.

---

## 5. Phased plan

### Phase D1 — Log-sequence anomaly detector on auth logs (highest value, lowest cost, start here)

*Persona: Backend Architect.*

This is the recommended starting point given your setup (solo dev, Windows+WSL, SQLite, no GPU). Text-log processing runs fine on CPU, network packet capture and deep learning training do not, as comfortably.

**No public datasets needed for this phase.** D1 trains unsupervised, directly on your own real auth logs, "learn what normal looks like, flag what deviates." The datasets in Section 4 (UNSW-NB15, CIC-IDS, etc.) are for D4's supervised step and later evaluation, not for D1, don't download them now, there's nothing here to use them for yet.

1. Feed auth logs (Wazuh's own archive logs, or `/var/log/auth.log`-equivalent from your enrolled agents) through **Drain3** to turn free-text lines into a small set of reusable templates.
2. Build simple count/sequence features from the templated logs (frequency per time window, sequence patterns).
3. Run **PyOD's Isolation Forest** (simplest, fastest to get working) as the first detector, flag statistical outliers in the feature set.
4. Emit each flagged anomaly as an alert following the exact shape, the `id` scheme, and the reserved `rule.id` range decided in Section 0.5, this is the critical design constraint, if this step is done correctly, zero changes are needed anywhere downstream in zuumb.
5. Confirm end to end: an anomaly from this detector shows up in the dashboard, gets triaged by the LLM, and can be correlated into an incident, exactly like a Wazuh-sourced alert would.
6. Confirm idempotency explicitly: run the detector twice over the same log window, the second run ingests zero new alerts, the same dedupe guarantee the Wazuh re-fetch path already relies on. If the second run adds duplicates, the `id` scheme from Section 0.5 point 1a is wrong, fix that, nothing downstream.

Checkpoint: `/ponytail-review` after each numbered step, `/ponytail-audit` once a real anomaly flows end to end through the whole existing zuumb pipeline unmodified.

### Phase D2 — Add a second detector, prove the "pluggable" architecture actually holds

*Persona: Backend Architect.*

1. Add a second, genuinely different detector source, either wrap **Kitsune** fed by **nfstream**-extracted flow features, or run **Slips** standalone and ingest its output.
2. This phase's real purpose is validating the architecture claim from Section 1, confirm zuumb's triage/correlation layer requires zero code changes to accept alerts from this second, independently-built source. If it does need changes, that's a sign the schema-normalization boundary in Phase D1 wasn't built cleanly, fix the normalizer, not zuumb's core.
3. Confirm both detectors' alerts can appear together in the same incident/chain when they genuinely relate (e.g. a network anomaly and an auth anomaly on the same host within the correlation window).

Checkpoint: `/ponytail-review`, `/ponytail-audit` once two independent detector sources both flow cleanly through the unmodified core.

**Continuous-operation status (added after D1/D2 shipped):** D1 runs continuously
as the `detector-authlog` docker-compose service — it polls the Wazuh alerts
index for `location: /var/log/auth.log` lines every 10 min (a `DetectorCursor`
row tracks progress + last-run time; the incidents page shows staleness). **D2
stays a manual CLI tool.** It requires a real network-flow feed — a Zeek/Suricata
`conn.log` or `nfstream` on a live segment — and this Wazuh-only lab produces
none (Wazuh captures no flow data natively, and the lab simulates hosts with a
log-line generator, not real connections). Do **not** stand up a synthetic flow
generator just to give D2 a schedule; that is the "always runs on empty input"
anti-pattern. D2 becomes continuous only once a genuine flow source exists.

### Phase D3 — LLM-assisted classification alongside the anomaly detectors

*Persona: Backend Architect, Security Engineer to review data handling.*

1. Add **SecureBERT 2.0** as a fast, cheap second-opinion classifier running on alert text, separate from (not replacing) the existing Claude-based triage call.
2. Use it specifically where it's genuinely useful, anomaly detectors from D1/D2 are typically good at flagging *that* something's unusual but bad at explaining *why* in plain language, this is exactly the gap an LLM is well suited to fill, narrating the surrounding context for an otherwise opaque anomaly score.
3. Keep this additive, not a replacement for the existing triage agent, the existing Claude-based verdict/confidence/reasoning stays the primary triage mechanism.

Checkpoint: `/ponytail-review`, `/ponytail-audit`.

### Phase D4 — Turn the analyst feedback loop into real, growing training data

*Persona: Backend Architect.*

This is the part of the plan that's genuinely novel to your environment, not just wiring up existing public tools.

**Label-source caveat, worth stating plainly so this phase doesn't over-promise:** `AnalystFeedback` captures a triage judgement, an analyst confirming or correcting a verdict (benign/suspicious/malicious) on an alert some detector already produced. It is not a raw "was this auth sequence actually an intrusion" label on unprocessed telemetry. That distinction matters: this feedback is a genuinely good label source for tuning triage thresholds or training a supervised model that improves on *already-detected* alerts, but it does not by itself teach a detector to recognize intrusions in raw, undetected telemetry, that would require separately labeled raw data, not corrections on alerts a detector already flagged.

1. Every analyst confirm/correct action already logged via `AnalystFeedback` (from the core buildplan) is a labeled training example, formalize this as the actual label source for future supervised models operating on already-detected alerts, not just a few-shot prompt input.
2. Set up a lightweight retrain loop: collect labeled corrections on a schedule (weekly is a reasonable start), retrain a simple supervised classifier (start with something interpretable, e.g. a gradient-boosted tree or logistic regression on engineered features, not a deep model yet) on the accumulated labels, evaluate against a held-out set, only promote a new model version if it doesn't regress accuracy.
3. Add basic drift monitoring, compare incoming feature distributions week over week against what the current model was trained on, flag when they've shifted meaningfully.
4. This is genuinely a small MLOps project on its own, budget it as such, don't treat it as a quick add-on to an existing weekend's work.

Checkpoint: `/ponytail-review` after each sub-step, `/ponytail-audit` once one full retrain cycle has actually run and a promoted model is measurably not worse than its predecessor on the held-out set.

### Phase D5 — Adversarial robustness check

*Persona: Security Engineer.*

1. Once at least one trained model exists (from D1 or D4), run it against the **Adversarial Robustness Toolbox** to test whether crafted input can fool it.
2. This directly addresses "adversaries adapt," a real and often-overlooked failure mode for any ML-based detector, worth doing at least once even at small scale, rather than assuming a working detector is a robust one.

Checkpoint: `/ponytail-review`, document findings even if not immediately acted on, this becomes useful context for anyone (including a future you) evaluating the detector's real-world reliability.

### Phase D6 — Public documentation of the detection track

*Persona: Product.*

1. Extend the README (and the marketing site's architecture section, if by this point it exists) to describe the pluggable detection architecture accurately, don't overstate a Phase D1-only implementation as a full multi-engine XDR if D2 through D5 aren't done yet.
2. Be explicit about what's rule-based (Wazuh, unchanged) versus ML-based (the new detectors) versus LLM-based (both the original triage agent and any D3 SecureBERT addition), this level of precision is itself a differentiator, most portfolio projects claiming "AI detection" don't actually explain which part is doing what.
3. Same directional-not-benchmark labeling discipline from Section 12 Group D applies here too, any detector accuracy numbers reported should be clearly framed by dataset size and methodology, not presented as certified performance.

Checkpoint: `/ponytail-review`, `/ponytail-audit` on the final documentation.

---

## 6. Ponytail and persona usage for this track

| Phase | Persona | Ponytail |
|---|---|---|
| D1 (log-sequence detector) | Backend Architect | review each step, audit at end |
| D2 (second detector, architecture proof) | Backend Architect | review each step, audit at end |
| D3 (SecureBERT second opinion) | Backend Architect + Security Engineer | review, audit |
| D4 (feedback loop → real training data) | Backend Architect | review each sub-step, audit after first full retrain cycle |
| D5 (adversarial robustness) | Security Engineer | review, document findings |
| D6 (documentation) | Product | review, audit final docs |

Same discipline as the core buildplan throughout, persona activated before starting a step, `/ponytail-review` after, `/ponytail-audit` at phase checkpoints, stop and show results before moving to the next phase. This track does not touch `RESPONSE_DRY_RUN` or anything in Section 11/12's response-gate logic, those stay exactly as they are, adding detection sources never changes what's allowed to act on a real machine.
