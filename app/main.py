"""FastAPI entrypoint.  Run:  uvicorn app.main:app --reload

Set WAZUH_LIVE_POLLING=true in .env to poll the Wazuh indexer on a schedule.
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db.session import get_session, init_db
from app.pipeline import run_pipeline_cycle
from app.web import auth
from app.web.routes import router

log = logging.getLogger("uvicorn.error")


def _poll_cycle() -> None:
    try:
        res = run_pipeline_cycle()
        log.info("wazuh poll: ingested=%s triaged=%s", res["ingested"], res["triaged"])
    except Exception:
        log.exception("wazuh poll cycle failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    scheduler = None
    if settings.wazuh_live_polling:
        from apscheduler.schedulers.background import BackgroundScheduler

        scheduler = BackgroundScheduler(daemon=True)
        scheduler.add_job(_poll_cycle, "interval", seconds=settings.wazuh_poll_seconds,
                          id="wazuh-poll", max_instances=1, coalesce=True,
                          next_run_time=datetime.now())  # first cycle immediately
        scheduler.start()
        log.info("wazuh live polling every %ss -> %s", settings.wazuh_poll_seconds,
                 settings.wazuh_api_url)
    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(title="zuumb", lifespan=lifespan)
init_db()

if settings.dashboard_password_reset:
    with get_session() as _s:
        _wiped = auth.clear_credential(_s)
    log.warning("DASHBOARD_PASSWORD_RESET is set: %s. Sign in with the .env credentials, "
                "set a new password in Settings, then unset the flag.",
                "custom credential wiped" if _wiped else "no custom credential to wipe")

if not auth.auth_enabled():
    log.warning("No dashboard credential: DASHBOARD_PASSWORD is blank and none was set "
                "in Settings. The dashboard and /tasks/*/approve are UNAUTHENTICATED.")

_OPEN = ("/login", "/login/help", "/logout")


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    """Login gate. CSRF is enforced per-route via auth.require_csrf."""
    path = request.url.path
    if not auth.auth_enabled() or path in _OPEN or path.startswith("/static/"):
        return await call_next(request)
    if auth.read_session(request) is not None:
        return await call_next(request)
    if request.method == "GET":
        return RedirectResponse(f"/login?next={path}", status_code=303)
    return PlainTextResponse("authentication required", status_code=401)


app.include_router(auth.router)
app.include_router(router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static")
