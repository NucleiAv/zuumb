"""Single-user session auth + CSRF, stdlib only (no new dependency).

Login credentials come from ONE of two places:
  * a `Credential` row  -> set by the user from /settings; while it exists the
    .env password is ignored.
  * else settings.dashboard_user / settings.dashboard_password (ships admin/admin).

Blank `dashboard_password` (and no Credential row) turns auth OFF for dev/test.
`dashboard_password_reset=true` wipes the Credential row on startup (see main.py),
so a forgotten Settings password falls back to the .env credentials.

Cookie: `b64url(payload).hex(hmac_sha256(secret, b64url(payload)))`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from app.config import settings
from app.db.models import Credential
from app.db.session import get_session

COOKIE = "zuumb_session"
_MAX_AGE = 60 * 60 * 12  # 12h
_PBKDF2_ROUNDS = 200_000

# Falls back to this when SESSION_SECRET is unset: unguessable, but per-process,
# so dev sessions do not survive a restart. Set SESSION_SECRET in prod.
_RUNTIME_SECRET = secrets.token_hex(32)

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()


# --- credential store -------------------------------------------------------

def _hash_pw(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), _PBKDF2_ROUNDS
    ).hex()


def get_credential(session) -> Credential | None:
    return session.get(Credential, 1)


def set_credential(session, username: str, password: str) -> None:
    salt = secrets.token_hex(16)
    row = get_credential(session) or Credential(id=1, username="", pw_hash="", pw_salt="")
    row.username, row.pw_salt, row.pw_hash = username, salt, _hash_pw(password, salt)
    row.updated_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()


def clear_credential(session) -> bool:
    row = get_credential(session)
    if row is None:
        return False
    session.delete(row)
    session.commit()
    return True


def check_login(username: str, password: str) -> bool:
    with get_session() as s:
        cred = get_credential(s)
    if cred is not None:
        return (hmac.compare_digest(username, cred.username)
                and hmac.compare_digest(_hash_pw(password, cred.pw_salt), cred.pw_hash))
    return (bool(settings.dashboard_password)
            and hmac.compare_digest(username, settings.dashboard_user)
            and hmac.compare_digest(password, settings.dashboard_password))


def auth_enabled() -> bool:
    """.env password is the master switch. Blank it (and clear any Credential) to
    run open. A Settings-set credential only changes *which* password works."""
    if settings.dashboard_password:
        return True
    with get_session() as s:
        return get_credential(s) is not None


# --- session cookie -------------------------------------------------------

def _secret() -> bytes:
    return (settings.session_secret or _RUNTIME_SECRET).encode()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: str) -> str:
    return hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()


def _make_cookie(user: str) -> str:
    body = _b64(json.dumps({"u": user, "csrf": secrets.token_hex(16),
                            "iat": int(time.time())}).encode())
    return f"{body}.{_sign(body)}"


def read_session(request: Request) -> dict | None:
    raw = request.cookies.get(COOKIE, "")
    if raw.count(".") != 1:
        return None
    body, sig = raw.split(".", 1)
    if not hmac.compare_digest(sig, _sign(body)):
        return None
    try:
        data = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(time.time()) - int(data.get("iat", 0)) > _MAX_AGE:
        return None
    return data


# --- CSRF ---------------------------------------------------------------------

def csrf_field(request: Request) -> Markup:
    """Jinja helper: the hidden CSRF input for a form, or nothing when auth is off."""
    sess = read_session(request) if auth_enabled() else None
    if not sess:
        return Markup("")
    return Markup(f'<input type="hidden" name="_csrf" value="{sess["csrf"]}">')


def require_csrf(request: Request, csrf: str = Form("", alias="_csrf")) -> None:
    """Dependency for every state-changing route. No-op when auth is off."""
    if not auth_enabled():
        return
    sess = read_session(request)
    if not sess or not hmac.compare_digest(str(csrf), str(sess.get("csrf", ""))):
        raise HTTPException(status_code=403, detail="bad or missing CSRF token")


# base.html needs these on whichever Jinja env renders it (login/settings pages
# use _templates here; the dashboard uses the one in routes.py, which registers
# the same two).
_templates.env.globals["csrf_field"] = csrf_field
_templates.env.globals["show_account_menu"] = (
    lambda req: auth_enabled() and read_session(req) is not None
)


# --- routes -----------------------------------------------------------------

def _safe_next(value: str) -> str:
    return value if value.startswith("/") and not value.startswith("//") else "/"


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", bad: int = 0):
    if not auth_enabled() or read_session(request):
        return RedirectResponse(_safe_next(next), status_code=303)
    return _templates.TemplateResponse(request, "login.html",
                                       {"next": _safe_next(next), "bad": bad})


@router.post("/login")
def login_submit(request: Request, password: str = Form(...),
                 username: str = Form(""), next: str = Form("/")):
    dest = _safe_next(next)
    if not (auth_enabled() and check_login(username or settings.dashboard_user, password)):
        return RedirectResponse(f"/login?next={dest}&bad=1", status_code=303)
    resp = RedirectResponse(dest, status_code=303)
    resp.set_cookie(COOKIE, _make_cookie(username or settings.dashboard_user),
                    max_age=_MAX_AGE, httponly=True, samesite="lax", path="/")
    return resp


@router.post("/logout")
def logout() -> Response:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp


@router.get("/login/help", response_class=HTMLResponse)
def login_help(request: Request):
    return _templates.TemplateResponse(request, "login_help.html", {})


def _current_user(request: Request) -> str:
    sess = read_session(request)
    return sess["u"] if sess else settings.dashboard_user


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, ok: int = 0, bad: str = ""):
    if auth_enabled() and read_session(request) is None:
        return RedirectResponse("/login?next=/settings", status_code=303)
    with get_session() as s:
        custom = get_credential(s) is not None
    return _templates.TemplateResponse(request, "settings.html",
                                       {"custom": custom, "user": _current_user(request),
                                        "ok": ok, "bad": bad})


@router.post("/settings/credentials")
def settings_credentials(
    request: Request,
    current_password: str = Form(...),
    new_username: str = Form(...),
    new_password: str = Form(...),
    csrf_ok: None = Depends(require_csrf),
):
    if auth_enabled() and read_session(request) is None:
        return RedirectResponse("/login?next=/settings", status_code=303)
    if not check_login(_current_user(request), current_password):
        return RedirectResponse("/settings?bad=current", status_code=303)
    if not new_username.strip() or len(new_password) < 8:
        return RedirectResponse("/settings?bad=weak", status_code=303)
    with get_session() as s:
        set_credential(s, new_username.strip(), new_password)
    resp = RedirectResponse("/settings?ok=1", status_code=303)
    resp.set_cookie(COOKIE, _make_cookie(new_username.strip()), max_age=_MAX_AGE,
                    httponly=True, samesite="lax", path="/")
    return resp
