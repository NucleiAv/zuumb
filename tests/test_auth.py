"""Group A / item 1: session login + CSRF + custom credentials + password reset."""
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db.session import get_session
from app.main import app
from app.web.auth import (
    _make_cookie,
    check_login,
    clear_credential,
    get_credential,
    read_session,
    set_credential,
)


@pytest.fixture
def secured(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_password", "s3cret")
    monkeypatch.setattr(settings, "session_secret", "unit-test-secret")
    monkeypatch.setattr(settings, "dashboard_user", "admin")
    return TestClient(app, follow_redirects=False)


def test_auth_off_by_default_leaves_everything_open():
    # no DASHBOARD_PASSWORD -> no gate, no CSRF
    c = TestClient(app)
    assert c.get("/").status_code == 200
    assert c.post("/tasks/999999/approve").status_code == 404  # got to the handler, not 401/403


def test_unauthenticated_get_redirects_to_login(secured):
    r = secured.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login?next=/"


def test_unauthenticated_post_is_401(secured):
    assert secured.post("/tasks/1/approve").status_code == 401


def test_login_bad_password_does_not_set_cookie(secured):
    r = secured.post("/login", data={"password": "wrong", "next": "/"})
    assert r.status_code == 303 and "bad=1" in r.headers["location"]
    assert "zuumb_session" not in r.cookies


def test_login_then_reach_the_dashboard(secured):
    r = secured.post("/login", data={"username": "admin", "password": "s3cret", "next": "/"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    secured.cookies.update(r.cookies)
    assert secured.get("/").status_code == 200


def test_post_without_csrf_token_is_403_even_when_logged_in(secured):
    secured.cookies.set("zuumb_session", _make_cookie("admin"))
    r = secured.post("/tasks/999999/approve")  # no _csrf field
    assert r.status_code == 403


def test_post_with_valid_csrf_passes_the_guard(secured):
    cookie = _make_cookie("admin")
    secured.cookies.set("zuumb_session", cookie)
    csrf = read_session(_Req(cookie))["csrf"]
    r = secured.post("/tasks/999999/approve", data={"_csrf": csrf})
    assert r.status_code == 404  # past the CSRF guard, into the handler (task missing)


def test_logout_clears_the_session(secured):
    secured.cookies.set("zuumb_session", _make_cookie("admin"))
    r = secured.post("/logout")
    assert r.status_code == 303
    secured.cookies.clear()
    assert secured.get("/").status_code == 303  # back to the login redirect


# --- custom credentials + reset --------------------------------------------

@pytest.fixture
def env_creds(monkeypatch):
    monkeypatch.setattr(settings, "dashboard_user", "admin")
    monkeypatch.setattr(settings, "dashboard_password", "admin")
    monkeypatch.setattr(settings, "session_secret", "unit-test-secret")


def test_env_default_credentials_work(env_creds):
    assert check_login("admin", "admin") is True
    assert check_login("admin", "nope") is False


def test_custom_credential_supersedes_the_env_password(env_creds):
    with get_session() as s:
        set_credential(s, "opsec", "longenough1")
    # the .env admin/admin no longer works; the custom one does
    assert check_login("admin", "admin") is False
    assert check_login("opsec", "longenough1") is True


def test_settings_change_needs_current_password_and_a_real_new_one(env_creds):
    c = TestClient(app, follow_redirects=False)
    c.cookies.set("zuumb_session", _make_cookie("admin"))
    csrf = read_session(_Req(c.cookies["zuumb_session"]))["csrf"]

    wrong = c.post("/settings/credentials", data={
        "current_password": "WRONG", "new_username": "opsec",
        "new_password": "longenough1", "_csrf": csrf})
    assert wrong.headers["location"] == "/settings?bad=current"

    weak = c.post("/settings/credentials", data={
        "current_password": "admin", "new_username": "opsec",
        "new_password": "short", "_csrf": csrf})
    assert weak.headers["location"] == "/settings?bad=weak"

    good = c.post("/settings/credentials", data={
        "current_password": "admin", "new_username": "opsec",
        "new_password": "longenough1", "_csrf": csrf})
    assert good.headers["location"] == "/settings?ok=1"
    assert check_login("opsec", "longenough1") and not check_login("admin", "admin")


def test_password_reset_flag_wipes_the_custom_credential(env_creds):
    with get_session() as s:
        set_credential(s, "opsec", "longenough1")
        assert get_credential(s) is not None
    # what main.py does on startup when DASHBOARD_PASSWORD_RESET is set
    with get_session() as s:
        assert clear_credential(s) is True
    assert check_login("admin", "admin") is True          # back to .env creds
    assert check_login("opsec", "longenough1") is False


def test_forgot_password_page_is_reachable_without_a_session(secured):
    r = secured.get("/login/help")
    assert r.status_code == 200 and "DASHBOARD_PASSWORD_RESET" in r.text


class _Req:
    """Minimal Request stand-in for read_session (only needs .cookies)."""
    def __init__(self, session_cookie: str):
        self.cookies = {"zuumb_session": session_cookie}
