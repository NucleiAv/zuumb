"""POC checkpoint: ingest synthetic alerts -> triage each -> correlate -> print.

    python -m scripts.run_poc                 # real Claude calls (needs ANTHROPIC_API_KEY)
    python -m scripts.run_poc --offline       # keyword heuristic, no API, for a dry demo
    python -m scripts.run_poc --limit 5

Re-runs are cheap: only alerts without a verdict get triaged.
"""
from __future__ import annotations

import argparse
from collections import defaultdict

from sqlmodel import select

from app.attack_chain.stitcher import stitch
from app.config import settings
from app.correlation.engine import correlate
from app.db.models import Alert, AttackChain, AttackChainIncident, Incident, IncidentAlert, Verdict
from app.db.session import get_session
from app.ingestion.wazuh_client import ingest
from app.response.playbooks import propose_for_incident
from app.triage.agent import triage_alert
from app.triage.offline import offline_verdict

DATA_DIR = "data/synthetic_alerts"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="use keyword heuristic, no API")
    ap.add_argument("--limit", type=int, default=None, help="triage at most N pending alerts")
    args = ap.parse_args()

    print(f"ingested {ingest(DATA_DIR)} new alert(s)\n")
    call = offline_verdict if args.offline else None

    with get_session() as s:
        alerts = s.exec(select(Alert).order_by(Alert.timestamp)).all()
        done = set(s.exec(select(Verdict.alert_id)).all())
        pending = [a for a in alerts if a.id not in done]
        if args.limit is not None:
            pending = pending[: args.limit]
        for i, a in enumerate(pending, 1):
            print(f"  triaging {i}/{len(pending)}  rule {a.rule_id} on {a.agent_name} ...")
            triage_alert(a, session=s, call=call)

        correlate(session=s)
        stitch(session=s)
        incident_ids = [i.id for i in s.exec(select(Incident)).all()]
        tasks_by_incident = {iid: propose_for_incident(iid, s) for iid in incident_ids}

        alerts = s.exec(select(Alert).order_by(Alert.timestamp)).all()
        verdicts = {v.alert_id: v for v in s.exec(select(Verdict)).all()}
        incidents = s.exec(select(Incident).order_by(Incident.id)).all()
        members = defaultdict(list)
        for link in s.exec(select(IncidentAlert)).all():
            members[link.incident_id].append(link.alert_id)
        chains = s.exec(select(AttackChain).order_by(AttackChain.id)).all()
        chain_stages = defaultdict(list)
        for link in s.exec(select(AttackChainIncident).order_by(AttackChainIncident.stage_order)).all():
            chain_stages[link.attack_chain_id].append(link.incident_id)

        _print_verdicts(alerts, verdicts)
        by_inc = {inc.id: inc for inc in incidents}
        _print_incidents(incidents, members, {a.id: a for a in alerts}, verdicts)
        _print_chains(chains, chain_stages, by_inc)
        _print_tasks(incidents, tasks_by_incident)


def _print_verdicts(alerts: list[Alert], verdicts: dict[int, Verdict]) -> None:
    print(f"\n{'TIME':16} {'HOST':11} {'RULE':6} {'VERDICT':10} {'CONF':5} {'MITRE':7} REASONING")
    print("-" * 100)
    for a in alerts:
        v = verdicts.get(a.id)
        if not v:
            continue
        reason = v.reasoning_text if len(v.reasoning_text) <= 60 else v.reasoning_text[:57] + "..."
        print(f"{a.timestamp:%Y-%m-%d %H:%M} {a.agent_name or '-':11} {a.rule_id:6} "
              f"{v.verdict:10} {v.confidence:<5.2f} {v.mitre_technique or '-':7} {reason}")


def _print_incidents(incidents, members, by_id, verdicts) -> None:
    multi = sum(1 for inc in incidents if len(members[inc.id]) > 1)
    print(f"\n{len(incidents)} incident(s); {multi} with >1 alert "
          f"(window {settings.correlation_window_minutes}m)")
    for inc in incidents:
        group = [by_id[aid] for aid in members[inc.id]]
        group.sort(key=lambda a: a.timestamp)
        span = f"{group[0].timestamp:%H:%M}-{group[-1].timestamp:%H:%M}"
        print(f"\n  [{inc.id}] {inc.title}  sev={inc.severity}  {span}")
        for a in group:
            v = verdicts.get(a.id)
            print(f"    - {a.timestamp:%H:%M} rule {a.rule_id:6} {a.rule_description[:50]:50} "
                  f"[{v.verdict if v else '-'}]")


def _print_chains(chains, stages, by_inc) -> None:
    print(f"\n{len(chains)} attack chain(s)")
    for c in chains:
        print(f"\n  [{c.id}] {c.title}")
        for order, inc_id in enumerate(stages[c.id]):
            inc = by_inc[inc_id]
            print(f"    stage {order}: incident [{inc.id}] {inc.title}  sev={inc.severity}")


def _print_tasks(incidents, tasks_by_incident) -> None:
    total = sum(len(v) for v in tasks_by_incident.values())
    print(f"\n{total} proposed response task(s) (human-approve only, nothing executes)")
    for inc in incidents:
        tasks = tasks_by_incident.get(inc.id, [])
        if not tasks:
            continue
        print(f"\n  incident [{inc.id}] {inc.title}")
        for t in tasks:
            print(f"    - [{t.priority:6}] {t.type:13} {t.title}  ({t.status})")


if __name__ == "__main__":
    main()
