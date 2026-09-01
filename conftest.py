# Presence at repo root puts it on sys.path so `import app...` works under pytest.
# Point every test at a throwaway SQLite file before app modules build the engine.
import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/test.db".replace("\\", "/"))
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-used")

import pytest  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_db():
    """Each test starts with empty tables — no cross-test/-file ordering coupling."""
    from app.db.session import engine

    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield
