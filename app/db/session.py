"""DB engine + session helpers."""
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy import inspect, text

from app.config import settings
from app.db import models  # noqa: F401  — registers tables on SQLModel.metadata

engine = create_engine(settings.database_url)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """create_all() adds new tables but never ALTERs an existing one. This adds
    any nullable column a model gained since the DB file was created — enough for
    this project's append-only schema, no migration framework needed."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in SQLModel.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have or not col.nullable:
                    continue
                ddl = col.type.compile(engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl}'))


def get_session() -> Session:
    # expire_on_commit=False: callers keep using returned objects after the session closes.
    return Session(engine, expire_on_commit=False)
