"""DB engine + session helpers."""
from sqlmodel import Session, SQLModel, create_engine

from app.config import settings
from app.db import models  # noqa: F401  — registers tables on SQLModel.metadata

engine = create_engine(settings.database_url)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    # expire_on_commit=False: callers keep using returned objects after the session closes.
    return Session(engine, expire_on_commit=False)
