"""app.system_settings: the deployment-wide nav-bar AI-detection toggle."""
from app.db.session import get_session
from app.system_settings import ai_triage_enabled, set_ai_triage_enabled


def test_defaults_to_enabled_with_no_row():
    with get_session() as s:
        assert ai_triage_enabled(s) is True


def test_set_and_read_back():
    with get_session() as s:
        set_ai_triage_enabled(s, False)
    with get_session() as s:
        assert ai_triage_enabled(s) is False

    with get_session() as s:
        set_ai_triage_enabled(s, True)
    with get_session() as s:
        assert ai_triage_enabled(s) is True
