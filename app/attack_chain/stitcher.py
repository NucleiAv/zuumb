"""Attack-chain stitcher: link incidents that share an entity, order them by
MITRE ATT&CK tactic (kill-chain order) into a lightweight attack narrative.

Deliberately simple — shared-entity grouping + tactic sort, no graph model.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from sqlmodel import Session, delete, select

from app.config import settings
from app.correlation.engine import entities
from app.db.models import Alert, AttackChain, AttackChainIncident, Incident, IncidentAlert, Verdict
from app.db.session import get_session, init_db

# ATT&CK Enterprise tactics in kill-chain order; index == stage rank.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
_UNKNOWN_RANK = len(TACTIC_ORDER)

# Fallback when an alert carries a technique id but no tactic name.
_TECHNIQUE_TACTIC = {
    "T1595": "Reconnaissance", "T1190": "Initial Access", "T1078": "Initial Access",
    "T1110": "Credential Access", "T1059": "Execution", "T1053": "Persistence",
    "T1041": "Exfiltration",
}


def tactic_rank(name: str) -> int:
    try:
        return TACTIC_ORDER.index(name)
    except ValueError:
        return _UNKNOWN_RANK


def _incident_tactics(alerts: list[Alert], technique_by_alert: dict[int, str | None]) -> set[str]:
    tactics: set[str] = set()
    for a in alerts:
        raw = json.loads(a.raw_json)
        tactics.update(raw.get("rule", {}).get("mitre", {}).get("tactic", []) or [])
        tech = technique_by_alert.get(a.id)
        if tech and tech in _TECHNIQUE_TACTIC:
            tactics.add(_TECHNIQUE_TACTIC[tech])
    return tactics


def _stage_rank(alerts: list[Alert], technique_by_alert: dict[int, str | None]) -> int:
    ranks = [tactic_rank(t) for t in _incident_tactics(alerts, technique_by_alert)]
    return min(ranks, default=_UNKNOWN_RANK)


def _signal_alerts(alerts: list[Alert], verdict_by_alert: dict[int, str]) -> list[Alert]:
    """Alerts with real attack signal — an "attack" rule group or a non-benign verdict.
    These are what a chain links on; routine alerts that merged into the same incident
    (a cron job, a login) must not contribute their entities. Falls back to all alerts."""
    hot = [
        a for a in alerts
        if verdict_by_alert.get(a.id) in ("malicious", "suspicious")
        or "attack" in json.loads(a.raw_json).get("rule", {}).get("groups", [])
    ]
    return hot or alerts


def stage_label(alerts: list[Alert], technique_by_alert: dict[int, str | None]) -> str:
    """The earliest tactic this stage's alerts touch — the stage's representative tactic."""
    tactics = _incident_tactics(alerts, technique_by_alert)
    return min(tactics, key=tactic_rank, default="Unknown")


def _group_by_shared_entity(incidents: list[Incident], ent: dict[int, set[str]]) -> list[list[Incident]]:
    parent = {i.id: i.id for i in incidents}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a in incidents:
        for b in incidents:
            if a.id < b.id and ent[a.id] & ent[b.id]:
                parent[find(a.id)] = find(b.id)

    groups: dict[int, list[Incident]] = defaultdict(list)
    for i in incidents:
        groups[find(i.id)].append(i)
    return list(groups.values())


def stitch(session: Session | None = None) -> list[AttackChain]:
    """Rebuild attack chains from the incidents in the DB. Idempotent.

    Analyst-set `status` is carried across the rebuild by matching a chain's exact
    set of incident ids. ponytail: derived-state rebuild — title/membership are
    recomputed; only status survives, keyed on that incident set.
    """
    init_db()
    own = session is None
    session = session or get_session()
    try:
        incidents = session.exec(select(Incident)).all()
        links = session.exec(select(IncidentAlert)).all()
        alerts = {a.id: a for a in session.exec(select(Alert)).all()}
        verdict_rows = session.exec(select(Verdict)).all()
        technique = {v.alert_id: v.mitre_technique for v in verdict_rows}
        verdict = {v.alert_id: v.verdict for v in verdict_rows}

        inc_alerts: dict[int, list[Alert]] = defaultdict(list)
        for link in links:
            inc_alerts[link.incident_id].append(alerts[link.alert_id])

        # A kill chain is built from malicious/suspicious activity, not benign noise:
        # only medium/high incidents are candidates, and a chain links on the entities
        # of the *attack-signal* alerts in each (not a cron job that merged in).
        candidates = [i for i in incidents if i.severity in ("medium", "high")]
        ent = {i.id: set().union(*(entities(a) for a in _signal_alerts(inc_alerts[i.id], verdict)), set())
               for i in candidates}
        rank = {i.id: _stage_rank(inc_alerts[i.id], technique) for i in candidates}

        # backstop: still drop an entity that somehow spans many incidents
        seen = Counter(e for es in ent.values() for e in es)
        common = {e for e, n in seen.items() if n > settings.chain_max_entity_spread}
        ent = {i: es - common for i, es in ent.items()}

        prior_members: dict[int, set] = defaultdict(set)
        for link in session.exec(select(AttackChainIncident)).all():
            prior_members[link.attack_chain_id].add(link.incident_id)
        prior_status = {frozenset(prior_members[c.id]): c.status
                        for c in session.exec(select(AttackChain)).all()}
        session.exec(delete(AttackChainIncident))
        session.exec(delete(AttackChain))
        session.commit()

        chains: list[AttackChain] = []
        for group in _group_by_shared_entity(candidates, ent):
            if len(group) < 2:
                continue
            ordered = sorted(group, key=lambda i: (rank[i.id], min(a.timestamp for a in inc_alerts[i.id])))
            first = stage_label(inc_alerts[ordered[0].id], technique)   # stage 0's tactic
            last = stage_label(inc_alerts[ordered[-1].id], technique)   # last stage's tactic
            status = prior_status.get(frozenset(i.id for i in ordered), "open")
            chain = AttackChain(title=f"{len(ordered)} stages: {first} -> {last}", status=status,
                                created_at=min(i.created_at for i in ordered))  # earliest stage, stable
            session.add(chain)
            session.commit()
            session.refresh(chain)
            session.add_all(
                AttackChainIncident(attack_chain_id=chain.id, incident_id=inc.id, stage_order=n)
                for n, inc in enumerate(ordered)
            )
            session.commit()
            chains.append(chain)
        return chains
    finally:
        if own:
            session.close()


def chain_quality(session: Session | None = None) -> list[dict]:
    """Phase 13 diagnostic. For each persisted chain, the entities that actually
    join each pair of adjacent stages, and a flag when a chain hangs on a single
    shared host across every link — the proxy/jump-box false-chain risk."""
    init_db()
    own = session is None
    session = session or get_session()
    try:
        alerts = {a.id: a for a in session.exec(select(Alert)).all()}
        verdict = {v.alert_id: v.verdict for v in session.exec(select(Verdict)).all()}
        inc_alerts: dict[int, list[Alert]] = defaultdict(list)
        for link in session.exec(select(IncidentAlert)).all():
            inc_alerts[link.incident_id].append(alerts[link.alert_id])

        def sig_ents(inc_id: int) -> set[str]:
            return set().union(*(entities(a) for a in _signal_alerts(inc_alerts[inc_id], verdict)), set())

        stages: dict[int, list[int]] = defaultdict(list)
        for link in session.exec(
            select(AttackChainIncident).order_by(AttackChainIncident.stage_order)
        ).all():
            stages[link.attack_chain_id].append(link.incident_id)

        out = []
        for c in session.exec(select(AttackChain).order_by(AttackChain.id)).all():
            ids = stages[c.id]
            links = [sorted(sig_ents(a) & sig_ents(b)) for a, b in zip(ids, ids[1:])]
            hub = bool(links) and all(len(s) == 1 and s[0].startswith("host:") for s in links)
            out.append({"chain_id": c.id, "title": c.title, "stages": len(ids),
                        "links": links, "flag": "hub-host" if hub else "ok"})
        return out
    finally:
        if own:
            session.close()
