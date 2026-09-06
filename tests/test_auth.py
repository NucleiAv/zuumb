"""Group A / item 1: session login + CSRF (only active when DASHBOARD_PASSWORD is set)."""
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.web.auth import _make_cookie, read_session


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


class _Req:
    """Minimal Request stand-in for read_session (only needs .cookies)."""
    def __init__(self, session_cookie: str):
        self.cookies = {"zuumb_session": session_cookie}
