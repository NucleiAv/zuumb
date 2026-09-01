"""FastAPI entrypoint.  Run:  uvicorn app.main:app --reload

Set WAZUH_LIVE_POLLING=true in .env to poll the Wazuh indexer on a schedule.
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db.session import init_db
from app.pipeline import run_pipeline_cycle
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
app.include_router(router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static")
