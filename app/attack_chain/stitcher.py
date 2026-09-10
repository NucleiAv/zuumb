"""Attack-chain stitcher: link incidents that share an entity *within a time
window*, order them by MITRE ATT&CK tactic (kill-chain order) into a lightweight
attack narrative, and score how much to trust the result.

Deliberately simple — shared-entity grouping + tactic sort, no graph model. A
chain is a *grouping hypothesis*, not a proven timeline: it never checks
causation. What it now does check (so a coincidence reads differently from a
real attack):
  - time proximity, not just a shared entity (item 1)
  - a per-chain confidence score, stored and shown, not a CLI-only diagnostic (item 2)
  - whether each stage's tactic label came from Wazuh or from a guess (item 3)
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime

from sqlmodel import Session, delete, select

from app.config import settings
from app.correlation.engine import entities, techniques_for
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
        # native rule.mitre.id first (via techniques_for), then the model's guess
        for tech in techniques_for(a, technique_by_alert.get(a.id)):
            if tech in _TECHNIQUE_TACTIC:
                tactics.add(_TECHNIQUE_TACTIC[tech])
    return tactics


def stage_label_with_source(
    alerts: list[Alert], technique_by_alert: dict[int, str | None]
) -> tuple[str, str]:
    """This stage's representative tactic (the earliest in kill-chain order) and
    where it came from: `native` (Wazuh's own `rule.mitre.tactic`), `fallback`
    (guessed from a technique id via `_TECHNIQUE_TACTIC`), or `unknown`.
    Native is stronger evidence and feeds the confidence score (item 3)."""
    native: set[str] = set()
    for a in alerts:
        native.update(json.loads(a.raw_json).get("rule", {}).get("mitre", {}).get("tactic", []) or [])
    if native:
        return min(native, key=tactic_rank), "native"

    guessed: set[str] = set()
    for a in alerts:
        for tech in techniques_for(a, technique_by_alert.get(a.id)):
            if tech in _TECHNIQUE_TACTIC:
                guessed.add(_TECHNIQUE_TACTIC[tech])
    if guessed:
        return min(guessed, key=tactic_rank), "fallback"
    return "Unknown", "unknown"


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


# --- time proximity (item 1) ---------------------------------------------------

def _incident_span(alerts: list[Alert]) -> tuple[datetime, datetime]:
    """(earliest, latest) alert timestamp for an incident."""
    ts = [a.timestamp for a in alerts]
    return (min(ts), max(ts)) if ts else (datetime.min, datetime.min)


def _gap_hours(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> float:
    """Hours between two incident spans; 0 if they overlap."""
    (a0, a1), (b0, b1) = a, b
    if a1 >= b0 and b1 >= a0:
        return 0.0
    delta = (b0 - a1) if b0 > a1 else (a0 - b1)
    return delta.total_seconds() / 3600.0


# --- confidence (item 2) -----------------------------------------------------

def _confidence(
    adj_shared: list[set[str]], adj_gaps: list[float], tactic_sources: list[str]
) -> tuple[str, str]:
    """(level, reasons) for one ordered chain. `adj_*` are between consecutive
    stages. level: high | medium | low. reasons: "; "-joined caveats, "" when high."""
    reasons: list[str] = []
    level = 2  # start at high, subtract for each weakness

    distinct_linkers = set().union(*adj_shared) if adj_shared else set()
    hub_host = bool(adj_shared) and all(
        len(s) == 1 and next(iter(s)).startswith("host:") for s in adj_shared
    )
    weak_link = any(not s for s in adj_shared)
    max_gap = max(adj_gaps, default=0.0)
    all_guessed = bool(tactic_sources) and all(s != "native" for s in tactic_sources)

    if hub_host:
        level -= 2
        reasons.append("every stage-to-stage link is the same single shared host — "
                       "likely a jump box, not one attacker moving through")
    if weak_link:
        level -= 2
        reasons.append("adjacent stages share no entity directly — they are only "
                       "linked transitively through another incident")
    if max_gap > settings.chain_strong_link_hours:
        level -= 1
        reasons.append(f"{max_gap:.0f}h between two linked stages, past the "
                       f"{settings.chain_strong_link_hours}h strong-link window")
    if all_guessed:
        level -= 1
        reasons.append("kill-chain tactic labels are guessed from technique ids, "
                       "not taken from Wazuh's own MITRE mapping")
    if len(distinct_linkers) <= 1:
        level -= 1
        reasons.append("the whole chain hangs on a single shared entity")

    level = max(0, min(2, level))
    return ("low", "medium", "high")[level], "; ".join(reasons)


def _group_by_shared_entity(
    incidents: list[Incident],
    ent: dict[int, set[str]],
    spans: dict[int, tuple[datetime, datetime]],
    max_link_hours: float,
) -> list[list[Incident]]:
    """Union incidents that share an entity AND fall within `max_link_hours` of
    each other. A shared entity alone is no longer enough (item 1)."""
    parent = {i.id: i.id for i in incidents}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a in incidents:
        for b in incidents:
            if (a.id < b.id and ent[a.id] & ent[b.id]
                    and _gap_hours(spans[a.id], spans[b.id]) <= max_link_hours):
                parent[find(a.id)] = find(b.id)

    groups: dict[int, list[Incident]] = defaultdict(list)
    for i in incidents:
        groups[find(i.id)].append(i)
    return list(groups.values())


def stitch(session: Session | None = None) -> list[AttackChain]:
    """Rebuild attack chains from the incidents in the DB. Idempotent.

    Analyst-set `status` (including the item-5 verdicts confirmed-narrative /
    false-chain) is carried across the rebuild by matching a chain's exact set of
    incident ids. `confidence`, `confidence_reasons`, and per-stage tactic labels
    are always recomputed — they are system judgements, not analyst state.
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

        # only medium/high incidents are chain candidates, and a chain links on
        # the entities of the *attack-signal* alerts in each (not a cron job).
        candidates = [i for i in incidents if i.severity in ("medium", "high")]
        ent = {i.id: set().union(*(entities(a) for a in _signal_alerts(inc_alerts[i.id], verdict)), set())
               for i in candidates}
        rank = {i.id: _stage_rank(inc_alerts[i.id], technique) for i in candidates}
        spans = {i.id: _incident_span(inc_alerts[i.id]) for i in candidates}

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
        for group in _group_by_shared_entity(candidates, ent, spans, settings.chain_max_link_hours):
            if len(group) < 2:
                continue
            ordered = sorted(group, key=lambda i: (rank[i.id], spans[i.id][0]))
            stage_tac = [stage_label_with_source(inc_alerts[i.id], technique) for i in ordered]
            adj_shared = [ent[a.id] & ent[b.id] for a, b in zip(ordered, ordered[1:])]
            adj_gaps = [_gap_hours(spans[a.id], spans[b.id]) for a, b in zip(ordered, ordered[1:])]
            conf, reasons = _confidence(adj_shared, adj_gaps, [src for _, src in stage_tac])

            first, last = stage_tac[0][0], stage_tac[-1][0]
            status = prior_status.get(frozenset(i.id for i in ordered), "open")
            chain = AttackChain(
                title=f"{len(ordered)} stages: {first} -> {last}", status=status,
                created_at=min(spans[i.id][0] for i in ordered),
                confidence=conf, confidence_reasons=reasons,
            )
            session.add(chain)
            session.commit()
            session.refresh(chain)
            session.add_all(
                AttackChainIncident(attack_chain_id=chain.id, incident_id=inc.id, stage_order=n,
                                    tactic=tac, tactic_source=src)
                for n, (inc, (tac, src)) in enumerate(zip(ordered, stage_tac))
            )
            session.commit()
            chains.append(chain)
        return chains
    finally:
        if own:
            session.close()


def chain_quality(session: Session | None = None) -> list[dict]:
    """CLI diagnostic. Per persisted chain: the entities joining each adjacent
    stage pair, and a flag for the two false-chain shapes the confidence score
    (item 2) now also penalises."""
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
            link_ents = [sorted(sig_ents(a) & sig_ents(b)) for a, b in zip(ids, ids[1:])]
            if link_ents and any(not s for s in link_ents):
                flag = "weak-link"
            elif link_ents and all(len(s) == 1 and s[0].startswith("host:") for s in link_ents):
                flag = "hub-host"
            else:
                flag = "ok"
            out.append({"chain_id": c.id, "title": c.title, "stages": len(ids),
                        "confidence": c.confidence, "links": link_ents, "flag": flag})
        return out
    finally:
        if own:
            session.close()
