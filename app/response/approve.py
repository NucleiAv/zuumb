"""Approve one proposed task.

Marks it done. If the task carries an allowlisted action (set by playbooks.py),
this either dispatches it via app.response.active_response or — in dry-run, the
config default — records the intent without touching a host. Either way a
`ResponseActionLog` row is written. Destructive actions need a second confirm;
real dispatches are rate-limited.

Orchestration only — the AR API call is active_response.dispatch. No raw
execution primitives here (tests/test_response.py checks).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from app.config import settings
from app.db.models import ResponseActionLog, Task
from app.response import active_response


class ConfirmRequired(Exception):
    """Destructive action approved without the second confirmation."""

    def __init__(self, action: str, incident_id: int):
        super().__init__(f"{action} needs a second confirmation")
        self.action, self.incident_id = action, incident_id


class RateLimited(Exception):
    """A real action was dispatched too recently."""


def _check_rate_limit(session: Session) -> None:
    gap = settings.response_rate_limit_seconds
    last = session.exec(
        select(ResponseActionLog)
        .where(ResponseActionLog.dry_run == False)  # noqa: E712 — SQL, not `is`
        .order_by(ResponseActionLog.created_at.desc())
    ).first()
    if not last:
        return
    lc = last.created_at
    lc = lc.astimezone(timezone.utc).replace(tzinfo=None) if lc.tzinfo else lc
    if datetime.now(timezone.utc).replace(tzinfo=None) - lc < timedelta(seconds=gap):
        raise RateLimited(f"another action was dispatched < {gap}s ago")


def approve_task(session: Session, task_id: int, *, approver: str = "analyst",
                 confirm: bool = False, dispatch=None) -> tuple[Task, ResponseActionLog | None]:
    task = session.get(Task, task_id)
    if task is None:
        raise ValueError(f"task {task_id} not found")

    spec = active_response.ACTIONS.get(task.action) if task.action else None
    log: ResponseActionLog | None = None
    if spec and task.action_target and task.agent_id:
        if spec["confirm"] and not confirm:
            raise ConfirmRequired(task.action, task.incident_id)

        dry = settings.response_dry_run
        if dry:
            ok, code, text = True, None, "dry-run — not dispatched"
        else:
            _check_rate_limit(session)
            res = (dispatch or active_response.dispatch)(
                task.action, task.action_target, task.agent_id)
            ok, code, text = res["ok"], res["status_code"], res["text"]

        log = ResponseActionLog(
            task_id=task.id, incident_id=task.incident_id, action=task.action,
            target=task.action_target, agent_id=task.agent_id, dry_run=dry,
            approver=approver, ok=ok, status_code=code, response_text=str(text)[:2000])
        session.add(log)

    task.status = "done"
    session.commit()
    session.refresh(task)
    if log is not None:
        session.refresh(log)
    return task, log
