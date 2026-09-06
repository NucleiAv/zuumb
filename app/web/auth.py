"""Single-user session auth + CSRF, stdlib only (no new dependency).

- `dashboard_password` unset  -> auth is OFF (dev/test); everything below no-ops.
- set                          -> a signed `zuumb_session` cookie is required; the
                                   session carries a CSRF token that every
                                   state-changing form must echo back.

The cookie is `b64url(payload).hex(hmac_sha256(secret, b64url(payload)))`.
"""
from __future__ import annotations

import base64
import hmac
import json
import secrets
import time
from hashlib import sha256

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from pathlib import Path

from app.config import settings

COOKIE = "zuumb_session"
_MAX_AGE = 60 * 60 * 12  # 12h

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()


def auth_enabled() -> bool:
    return bool(settings.dashboard_password)


def _secret() -> bytes:
    return (settings.session_secret or settings.dashboard_password or "zuumb-insecure-dev").encode()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: str) -> str:
    return hmac.new(_secret(), payload.encode(), sha256).hexdigest()


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


# --- routes -----------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", bad: int = 0):
    if not auth_enabled() or read_session(request):
        return RedirectResponse(next or "/", status_code=303)
    return _templates.TemplateResponse(request, "login.html", {"next": next or "/", "bad": bad})


@router.post("/login")
def login_submit(request: Request, password: str = Form(...),
                 username: str = Form(""), next: str = Form("/")):
    dest = next if next.startswith("/") else "/"
    user_ok = hmac.compare_digest(username or settings.dashboard_user, settings.dashboard_user)
    pass_ok = hmac.compare_digest(password, settings.dashboard_password)
    if not (auth_enabled() and user_ok and pass_ok):
        return RedirectResponse(f"/login?next={dest}&bad=1", status_code=303)
    resp = RedirectResponse(dest, status_code=303)
    resp.set_cookie(COOKIE, _make_cookie(settings.dashboard_user), max_age=_MAX_AGE,
                    httponly=True, samesite="lax", path="/")
    return resp


@router.post("/logout")
def logout() -> Response:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp
