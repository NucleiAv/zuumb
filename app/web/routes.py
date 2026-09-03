"""Dashboard routes: incidents list + incident detail."""
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import select

from app.attack_chain.stitcher import TACTIC_ORDER, _incident_tactics, stage_label
from app.correlation.engine import entities, incident_severity
from app.config import settings
from app.db.models import (
    Alert,
    AnalystFeedback,
    AttackChain,
    AttackChainIncident,
    Incident,
    IncidentAlert,
    ResponseActionLog,
    Task,
    Verdict,
)
from app.db.session import get_session
from app.feedback.logger import record_override
from app.response.approve import ConfirmRequired, RateLimited, approve_task
from app.response.playbooks import propose_for_incident
from app.web.stats import DAYS, compute_stats

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# every timestamp goes to the browser as ISO-8601 UTC; the client renders it local
templates.env.filters["isoz"] = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
# cache-bust /static/charts.js on its mtime, so a restart always invalidates a stale bundle
templates.env.globals["charts_v"] = int(
    (Path(__file__).parent / "static" / "charts.js").stat().st_mtime
)


_FILTER_COLS = {"rule": Alert.rule_id, "src_ip": Alert.src_ip, "host": Alert.agent_name}
_PER_PAGE = 50          # incidents per page
_ALERTS_CAP = 200       # alert rows rendered per incident detail (?all=1 for the rest)


def _instant(s: str | None) -> datetime | None:
    """ISO-8601 (with offset, as the client always sends) -> naive-UTC datetime."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)  # 3.11+ parses the trailing Z
    except ValueError:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _time_window(p) -> tuple[datetime | None, datetime | None]:
    """(since, until) as naive-UTC from ?from=&to= — the client computes these from
    the viewer's local range and sends explicit UTC instants."""
    return _instant(p.get("from")), _instant(p.get("to"))


@router.get("/", response_class=HTMLResponse)
def incidents_list(request: Request):
    p = request.query_params
    since, until = _time_window(p)
    entity = {k: v for k in _FILTER_COLS if (v := p.get(k))}
    mitre, dow, hour = p.get("mitre"), p.get("dow"), p.get("hour")
    verdict, severity = p.get("verdict"), p.get("severity")
    tzmin = int(p.get("tzmin") or 0)  # JS getTimezoneOffset(): minutes to add to local -> UTC
    sort_dir = "asc" if p.get("dir") == "asc" else "desc"

    with get_session() as s:
        stats = compute_stats(s, since, until)
        links = s.exec(select(IncidentAlert)).all()
        counts = Counter(link.incident_id for link in links)
        order = Incident.created_at.asc() if sort_dir == "asc" else Incident.created_at.desc()
        incidents = s.exec(select(Incident).order_by(order, Incident.id.desc())).all()

        keep: set | None = None

        def narrow(alert_ids: set) -> None:
            nonlocal keep
            ids = {link.incident_id for link in links if link.alert_id in alert_ids}
            keep = ids if keep is None else keep & ids

        if since or until:
            aq = select(Alert.id)
            if since:
                aq = aq.where(Alert.timestamp >= since)
            if until:
                aq = aq.where(Alert.timestamp <= until)
            narrow(set(s.exec(aq).all()))
        if entity:
            aq = select(Alert.id)
            for k, v in entity.items():
                aq = aq.where(_FILTER_COLS[k] == v)
            narrow(set(s.exec(aq).all()))
        if mitre:
            narrow({v.alert_id for v in
                    s.exec(select(Verdict).where(Verdict.mitre_technique == mitre)).all()})
        if verdict:
            narrow({v.alert_id for v in
                    s.exec(select(Verdict).where(Verdict.verdict == verdict)).all()})
        if dow is not None and hour is not None:
            di, hi = int(dow), int(hour)
            # weekday/hour has no SQLite fn -> filter in Python (fine at POC scale).
            # tzmin shifts the stored UTC instant into the viewer's local zone first,
            # so the cell matches the heatmap the viewer actually clicked.
            local = lambda ts: ts - timedelta(minutes=tzmin)  # noqa: E731
            narrow({a.id for a in s.exec(select(Alert)).all()
                    if local(a.timestamp).weekday() == di and local(a.timestamp).hour == hi})

        if keep is not None:
            incidents = [i for i in incidents if i.id in keep]

        if severity:
            incidents = [i for i in incidents if i.severity == severity]

    active = dict(entity)
    if mitre:
        active["mitre"] = mitre
    if verdict:
        active["verdict"] = verdict
    if severity:
        active["severity"] = severity
    if dow is not None and hour is not None:
        active["cell"] = f"{DAYS[int(dow)]} {int(hour):02d}:00"

    total = len(incidents)
    page = max(1, int(p.get("page") or 1))
    pages = max(1, -(-total // _PER_PAGE))
    page = min(page, pages)
    incidents = incidents[(page - 1) * _PER_PAGE: page * _PER_PAGE]

    return templates.TemplateResponse(request, "incidents.html", {
        "incidents": incidents, "counts": counts, "stats": stats,
        "filters": active, "sort_dir": sort_dir, "time_range": p.get("range"),
        "total": total, "page": page, "pages": pages,
        "date_from": p.get("fromd"), "date_to": p.get("tod"),  # raw local dates, for the inputs
    })


@router.get("/incidents", include_in_schema=False)  # also catches /incidents/ via slash redirect
def incidents_index():
    return RedirectResponse("/")


_SEV_RANK = {"low": 0, "medium": 1, "high": 2}


@router.get("/chains", response_class=HTMLResponse)
def chains_list(request: Request):
    with get_session() as s:
        chains = s.exec(select(AttackChain).order_by(AttackChain.id.desc())).all()
        links = s.exec(select(AttackChainIncident)).all()
        incidents = {i.id: i for i in s.exec(select(Incident)).all()}
        alert_counts = Counter(la.incident_id for la in s.exec(select(IncidentAlert)).all())

        members: dict[int, list[int]] = {}
        for link in links:
            members.setdefault(link.attack_chain_id, []).append(link.incident_id)

    rows = []
    for c in chains:
        incs = [incidents[i] for i in members.get(c.id, [])]
        worst = max((i.severity for i in incs), key=_SEV_RANK.get, default="low")
        rows.append({
            "chain": c,
            "stages": len(incs),
            "severity": worst,
            "alerts": sum(alert_counts.get(i.id, 0) for i in incs),
        })
    return templates.TemplateResponse(request, "chains.html", {"rows": rows})


@router.get("/chains/{chain_id}", response_class=HTMLResponse)
def chain_detail(request: Request, chain_id: int):
    with get_session() as s:
        chain = s.get(AttackChain, chain_id)
        if chain is None:
            raise HTTPException(status_code=404, detail="attack chain not found")
        links = s.exec(
            select(AttackChainIncident)
            .where(AttackChainIncident.attack_chain_id == chain_id)
            .order_by(AttackChainIncident.stage_order)
        ).all()
        inc_ids = [link.incident_id for link in links]
        incidents = {i.id: i for i in s.exec(select(Incident).where(Incident.id.in_(inc_ids))).all()}
        alerts_by_inc: dict[int, list[int]] = {}
        for il in s.exec(select(IncidentAlert).where(IncidentAlert.incident_id.in_(inc_ids))).all():
            alerts_by_inc.setdefault(il.incident_id, []).append(il.alert_id)
        alert_ids = [aid for ids in alerts_by_inc.values() for aid in ids]
        all_alerts = {a.id: a for a in s.exec(select(Alert).where(Alert.id.in_(alert_ids))).all()}
        technique = {
            v.alert_id: v.mitre_technique
            for v in s.exec(select(Verdict).where(Verdict.alert_id.in_(alert_ids))).all()
        }
        stages, present, seen_entities = [], set(), set()
        for link in links:
            inc = incidents[link.incident_id]
            inc_alerts = [all_alerts[aid] for aid in alerts_by_inc.get(inc.id, [])]
            ents = set().union(*(entities(a) for a in inc_alerts), set())
            shared = sorted(ents & seen_entities)  # item 5: link back to earlier stages
            seen_entities |= ents
            present |= _incident_tactics(inc_alerts, technique)
            stages.append({
                "order": link.stage_order,
                "incident": inc,
                "tactic": stage_label(inc_alerts, technique),
                "alert_count": len(inc_alerts),
                "shared_with_earlier": shared,
            })
        worst = max((st["incident"].severity for st in stages), key=_SEV_RANK.get, default="low")
        kill_chain = [{"name": t, "present": t in present} for t in TACTIC_ORDER]
    return templates.TemplateResponse(request, "chain_detail.html", {
        "chain": chain, "stages": stages, "severity": worst, "kill_chain": kill_chain,
    })


@router.post("/chains/{chain_id}/status")
def chain_status(chain_id: int, status: str = Form(...)):
    if status not in ("open", "investigating", "contained", "closed"):
        raise HTTPException(status_code=400, detail="invalid chain status")
    with get_session() as s:
        chain = s.get(AttackChain, chain_id)
        if chain is None:
            raise HTTPException(status_code=404, detail="attack chain not found")
        chain.status = status
        s.commit()
    return RedirectResponse(f"/chains/{chain_id}", status_code=303)


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: int):
    with get_session() as s:
        incident = s.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        alert_ids = [
            link.alert_id
            for link in s.exec(
                select(IncidentAlert).where(IncidentAlert.incident_id == incident_id)
            ).all()
        ]
        total_alerts = len(alert_ids)
        show_all = request.query_params.get("all") == "1"
        aq = select(Alert).where(Alert.id.in_(alert_ids)).order_by(Alert.timestamp)
        if not show_all:
            aq = aq.limit(_ALERTS_CAP)
        alerts = s.exec(aq).all()
        verdicts = {  # keep the latest model verdict per alert
            v.alert_id: v
            for v in s.exec(
                select(Verdict).where(Verdict.alert_id.in_(alert_ids)).order_by(Verdict.created_at)
            ).all()
        }
        overrides = {  # latest analyst override per verdict
            fb.verdict_id: fb
            for fb in s.exec(
                select(AnalystFeedback)
                .where(AnalystFeedback.verdict_id.in_([v.id for v in verdicts.values()]))
                .order_by(AnalystFeedback.created_at)
            ).all()
        }
        tasks = propose_for_incident(incident_id, s)  # idempotent: suggests, never executes
        dispatches = s.exec(
            select(ResponseActionLog)
            .where(ResponseActionLog.incident_id == incident_id)
            .order_by(ResponseActionLog.created_at.desc())
        ).all()
    rows = []
    for a in alerts:
        v = verdicts.get(a.id)
        rows.append((a, v, overrides.get(v.id) if v else None))
    return templates.TemplateResponse(request, "incident_detail.html", {
        "incident": incident, "rows": rows, "tasks": tasks, "dispatches": dispatches,
        "total_alerts": total_alerts, "shown_alerts": len(rows), "show_all": show_all,
        "alerts_cap": _ALERTS_CAP,
        "dry_run": settings.response_dry_run,
        "confirm_task": request.query_params.get("confirm"),
    })


@router.get("/audit", response_class=HTMLResponse)
def audit_log(request: Request):
    """Every approved active-response dispatch, dry-run included."""
    with get_session() as s:
        logs = s.exec(
            select(ResponseActionLog).order_by(ResponseActionLog.created_at.desc())
        ).all()
    return templates.TemplateResponse(request, "audit.html", {
        "logs": logs, "dry_run": settings.response_dry_run,
    })


def _flatten(obj, prefix: str = ""):
    """Every leaf of a nested dict/list as (dotted-path, value). Deterministic, lossless."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _flatten(v, f"{prefix}{i}.")
    else:
        yield prefix.rstrip("."), obj


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: int):
    """Single-alert view. Renders ONLY stored data — the raw Wazuh alert and the
    triage verdict/reasoning already in the DB. No LLM call is made here."""
    with get_session() as s:
        alert = s.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        verdict = s.exec(
            select(Verdict).where(Verdict.alert_id == alert_id).order_by(Verdict.created_at.desc())
        ).first()
        link = s.exec(select(IncidentAlert).where(IncidentAlert.alert_id == alert_id)).first()

    raw = json.loads(alert.raw_json)
    normalized = [
        ("timestamp", alert.timestamp),
        ("rule_id", alert.rule_id),
        ("rule_description", alert.rule_description),
        ("agent / host", alert.agent_name),
        ("src_ip", alert.src_ip),
        ("dst_ip", alert.dst_ip),
        ("user", alert.user),
    ]
    return templates.TemplateResponse(request, "alert_detail.html", {
        "alert": alert,
        "incident_id": link.incident_id if link else None,
        "normalized": normalized,
        "raw_fields": sorted(_flatten(raw)),
        "raw_json_pretty": json.dumps(raw, indent=2, sort_keys=True),
        "verdict": verdict,
    })


@router.post("/tasks/{task_id}/approve")
def task_approve(task_id: int, confirm: str = Form("")):
    """Approve a task. Plain tasks just flip to done; an action-tagged task also
    dispatches (or, in dry-run, records intent) via the active-response path."""
    with get_session() as s:
        try:
            task, _log = approve_task(s, task_id, confirm=bool(confirm))
        except ValueError:
            raise HTTPException(status_code=404, detail="task not found")
        except ConfirmRequired as e:
            return RedirectResponse(f"/incidents/{e.incident_id}?confirm={task_id}",
                                    status_code=303)
        except RateLimited as e:
            raise HTTPException(status_code=429, detail=str(e))
        dest = task.incident_id
    return RedirectResponse(f"/incidents/{dest}", status_code=303)


@router.post("/verdicts/{verdict_id}/override")
def verdict_override(
    request: Request, verdict_id: int, analyst_verdict: str = Form(...), note: str = Form("")
):
    """Log an analyst's corrected verdict. Feeds the next triage prompt (few-shot) and
    recomputes just this incident's severity with the overridden verdict in place —
    no re-correlation, no re-stitch (see the scope note in stitcher/correlate)."""
    with get_session() as s:
        verdict = s.get(Verdict, verdict_id)
        if verdict is None:
            raise HTTPException(status_code=404, detail="verdict not found")
        link = s.exec(
            select(IncidentAlert).where(IncidentAlert.alert_id == verdict.alert_id)
        ).first()
        try:
            record_override(s, verdict_id, analyst_verdict, note)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        new_severity = None
        if link is not None:
            incident = s.get(Incident, link.incident_id)
            alert_ids = [
                il.alert_id for il in
                s.exec(select(IncidentAlert).where(IncidentAlert.incident_id == incident.id)).all()
            ]
            alerts = s.exec(select(Alert).where(Alert.id.in_(alert_ids))).all()
            verdicts = {
                v.alert_id: v.verdict for v in
                s.exec(select(Verdict).where(Verdict.alert_id.in_(alert_ids))).all()
            }
            verdicts[verdict.alert_id] = analyst_verdict  # analyst's call wins for this alert
            new_severity = incident_severity(alerts, verdicts)
            incident.severity = new_severity
            s.commit()

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"analyst_verdict": analyst_verdict, "severity": new_severity})
    dest = f"/incidents/{link.incident_id}" if link else "/"
    return RedirectResponse(dest, status_code=303)
