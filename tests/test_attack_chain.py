from collections import defaultdict
from datetime import datetime, timedelta

from sqlmodel import delete, select

from app.attack_chain.stitcher import _group_by_shared_entity, stitch, tactic_rank
from app.correlation.engine import correlate
from app.db.models import Alert, AttackChain, AttackChainIncident, Incident, IncidentAlert
from app.db.session import get_session
from app.ingestion.wazuh_client import ingest
from app.triage.agent import triage_alert
from app.triage.offline import offline_verdict

DATA = "data/synthetic_alerts/batch01.jsonl"


def _ingest_triage_correlate():
    """Chains need incident severities, which come from verdicts."""
    ingest(DATA)
    with get_session() as s:
        for a in s.exec(select(Alert)).all():
            triage_alert(a, session=s, call=offline_verdict)
    correlate(window_minutes=30)


def test_tactic_rank_follows_kill_chain_order():
    assert tactic_rank("Reconnaissance") < tactic_rank("Initial Access") < tactic_rank("Exfiltration")
    assert tactic_rank("nonsense") == tactic_rank("also nonsense")  # unknown -> stable sentinel


def test_group_by_shared_entity_is_transitive():
    incs = [Incident(id=1, title="a"), Incident(id=2, title="b"), Incident(id=3, title="c")]
    ent = {1: {"host:h1"}, 2: {"host:h1", "ip:9.9.9.9"}, 3: {"user:bob"}}
    t = datetime(2026, 1, 1, 12, 0)
    spans = {1: (t, t), 2: (t, t), 3: (t, t)}  # all simultaneous -> time never blocks
    sizes = sorted(len(g) for g in _group_by_shared_entity(incs, ent, spans, 72))
    assert sizes == [1, 2]  # 1<->2 via host:h1; 3 alone


def test_group_by_shared_entity_wont_link_incidents_beyond_the_time_window():
    incs = [Incident(id=1, title="a"), Incident(id=2, title="b")]
    ent = {1: {"host:h1"}, 2: {"host:h1"}}  # same host
    monday = datetime(2026, 1, 5, 9, 0)
    thursday = datetime(2026, 1, 8, 9, 0)  # ~72h later, exactly at the edge
    spans = {1: (monday, monday), 2: (thursday, thursday)}
    # inside the window they link, past it they don't
    assert sorted(len(g) for g in _group_by_shared_entity(incs, ent, spans, 72)) == [2]
    assert sorted(len(g) for g in _group_by_shared_entity(incs, ent, spans, 48)) == [1, 1]


def _incident_rule_ids():
    with get_session() as s:
        alerts = {a.id: a for a in s.exec(select(Alert)).all()}
        rules = defaultdict(set)
        for il in s.exec(select(IncidentAlert)).all():
            rules[il.incident_id].add(alerts[il.alert_id].rule_id)
    return rules


def test_stitch_orders_web_attack_recon_before_exfil():
    _ingest_triage_correlate()
    chains = stitch()
    assert chains

    rules = _incident_rule_ids()
    with get_session() as s:
        links = s.exec(select(AttackChainIncident)).all()
    by_chain = defaultdict(list)
    for link in links:
        by_chain[link.attack_chain_id].append(link)

    web = next(
        (sorted(ls, key=lambda x: x.stage_order)
         for ls in by_chain.values()
         if any("92300" in rules[x.incident_id] for x in ls)),
        None,
    )
    assert web is not None and len(web) == 2
    assert "31151" in rules[web[0].incident_id]    # stage 0 = recon
    assert "92300" in rules[web[-1].incident_id]   # last stage = exfiltration


def test_stitch_is_idempotent():
    _ingest_triage_correlate()
    n = len(stitch())
    assert n and len(stitch()) == n


def _seed_chain_pair(a_ent, b_ent):
    """Two attack incidents A (recon) -> B (execution). a_ent/b_ent are (host, srcip)."""
    import json as _json
    from app.db.models import Verdict
    raw = lambda tac: _json.dumps({"rule": {"groups": ["attack"], "mitre": {"tactic": [tac]}}})
    with get_session() as s:
        rows = [
            ("A", *a_ent, "Reconnaissance"),
            ("B", *b_ent, "Execution"),
        ]
        for tag, host, ip, tac in rows:
            al = Alert(wazuh_alert_id=tag, timestamp=datetime(2026, 8, 28, 14, 0), rule_id="1",
                       rule_description="d", agent_name=host, src_ip=ip, raw_json=raw(tac))
            s.add(al); s.commit(); s.refresh(al)
            s.add(Verdict(alert_id=al.id, verdict="malicious", confidence=0.9,
                          reasoning_text="x", model_version="t"))
            inc = Incident(title=tag, severity="high")
            s.add(inc); s.commit(); s.refresh(inc)
            s.add(IncidentAlert(incident_id=inc.id, alert_id=al.id)); s.commit()


def test_chain_quality_flags_hub_host_and_clears_ip_linked():
    from app.attack_chain.stitcher import chain_quality
    _seed_chain_pair(("jump-01", "203.0.113.5"), ("jump-01", "203.0.113.9"))  # only host shared
    assert stitch()
    q = chain_quality()
    assert len(q) == 1 and q[0]["flag"] == "hub-host"
    assert q[0]["links"] == [["host:jump-01"]]

    with get_session() as s:  # fresh: a chain linked by a real shared IP
        for m in (Alert, Incident, IncidentAlert, AttackChain, AttackChainIncident):
            s.exec(delete(m))
        s.commit()
    _seed_chain_pair(("web-a", "198.51.100.7"), ("web-b", "198.51.100.7"))  # shared srcip
    stitch()
    assert chain_quality()[0]["flag"] == "ok"


def test_chain_title_reflects_first_and_last_stage_tactic():
    """Bug fix: title = tactic of stage 0 -> tactic of the last stage (matches the table),
    not a canonical-latest lookup."""
    _ingest_triage_correlate()
    from app.attack_chain.stitcher import stage_label_with_source
    from app.db.models import Verdict

    def stage_label(alerts, tech):
        return stage_label_with_source(alerts, tech)[0]

    rules = _incident_rule_ids()
    chains = stitch()
    with get_session() as s:
        all_alerts = {a.id: a for a in s.exec(select(Alert)).all()}
        tech = {v.alert_id: v.mitre_technique for v in s.exec(select(Verdict)).all()}
        links = defaultdict(list)
        for la in s.exec(select(IncidentAlert)).all():
            links[la.incident_id].append(all_alerts[la.alert_id])
        chain_links = defaultdict(list)
        for cl in s.exec(select(AttackChainIncident)).all():
            chain_links[cl.attack_chain_id].append(cl)

    web = next(c for c in chains
               if any("31151" in rules[cl.incident_id]
                      for cl in chain_links[c.id]))
    stages = sorted(chain_links[web.id], key=lambda x: x.stage_order)
    first = stage_label(links[stages[0].incident_id], tech)
    last = stage_label(links[stages[-1].incident_id], tech)
    assert web.title == f"{len(stages)} stages: {first} -> {last}"
    assert "Reconnaissance" in web.title  # stage 0 of the web attack is recon


def test_status_is_preserved_across_restitch_when_membership_unchanged():
    _ingest_triage_correlate()
    chains = stitch()
    with get_session() as s:
        c = s.get(AttackChain, chains[0].id)
        c.status = "contained"
        s.commit()
    stitch()  # rebuild
    with get_session() as s:
        statuses = [c.status for c in s.exec(select(AttackChain)).all()]
    assert "contained" in statuses


def test_low_severity_incidents_do_not_chain():
    with get_session() as s:
        for n in range(2):
            a = Alert(wazuh_alert_id=f"lo-{n}", timestamp=datetime(2026, 8, 28, 2 + n),
                      rule_id="2501", rule_description="Cron job executed.",
                      agent_name="app-03", raw_json='{"rule":{"groups":["cron"]}}')
            s.add(a); s.commit(); s.refresh(a)
            inc = Incident(title="app-03", severity="low")
            s.add(inc); s.commit(); s.refresh(inc)
            s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id)); s.commit()
    assert stitch() == []


def test_lone_incident_makes_no_chain():
    with get_session() as s:
        a = Alert(wazuh_alert_id="solo", timestamp=datetime(2026, 8, 28, 1, 0),
                  rule_id="1", rule_description="d", agent_name="only-host", raw_json="{}")
        s.add(a)
        s.commit()
        s.refresh(a)
        inc = Incident(title="only-host", severity="low")
        s.add(inc)
        s.commit()
        s.refresh(inc)
        s.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        s.commit()
    assert stitch() == []


# --- chain hardening: the Monday-recon / Thursday-exfil coincidence -------------

def _seed_two(host_a, ip_a, tac_a, ts_a, host_b, ip_b, tac_b, ts_b):
    """Two high-severity attack incidents with explicit hosts/IPs, tactics, times."""
    import json as _json
    from app.db.models import Verdict
    raw = lambda tac: _json.dumps({"rule": {"groups": ["attack"], "mitre": {"tactic": [tac]}}})
    with get_session() as s:
        for tag, host, ip, tac, ts in [("A", host_a, ip_a, tac_a, ts_a),
                                       ("B", host_b, ip_b, tac_b, ts_b)]:
            al = Alert(wazuh_alert_id=tag, timestamp=ts, rule_id="1", rule_description="d",
                       agent_name=host, src_ip=ip, raw_json=raw(tac))
            s.add(al); s.commit(); s.refresh(al)
            s.add(Verdict(alert_id=al.id, verdict="malicious", confidence=0.9,
                          reasoning_text="x", model_version="t"))
            inc = Incident(title=tag, severity="high")
            s.add(inc); s.commit(); s.refresh(inc)
            s.add(IncidentAlert(incident_id=inc.id, alert_id=al.id)); s.commit()


_MON = datetime(2026, 1, 5, 9, 0)


def test_far_apart_coincidence_on_one_host_does_not_form_a_chain():
    # Monday recon scan + Thursday exfil on web-01, ~72h+ apart, nothing else shared
    _seed_two("web-01", "203.0.113.9", "Reconnaissance", _MON,
              "web-01", "198.51.100.4", "Exfiltration", _MON + timedelta(hours=80))
    assert stitch() == []  # beyond chain_max_link_hours -> not linked at all


def test_mid_range_coincidence_on_one_host_is_low_confidence_not_a_strong_chain():
    # same coincidence but ~48h apart: links, but every warning fires
    _seed_two("web-01", "203.0.113.9", "Reconnaissance", _MON,
              "web-01", "198.51.100.4", "Exfiltration", _MON + timedelta(hours=48))
    chains = stitch()
    assert len(chains) == 1
    c = chains[0]
    assert c.confidence == "low"
    assert "single shared host" in c.confidence_reasons or "single shared entity" in c.confidence_reasons
    assert "strong-link window" in c.confidence_reasons


def test_tight_multi_entity_chain_is_not_low_confidence():
    # same host AND same source IP, ~2h apart, native tactics -> a real-looking chain
    _seed_two("web-01", "203.0.113.9", "Reconnaissance", _MON,
              "web-01", "203.0.113.9", "Execution", _MON + timedelta(hours=2))
    chains = stitch()
    assert len(chains) == 1 and chains[0].confidence in ("high", "medium")
