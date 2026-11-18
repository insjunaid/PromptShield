"""The admin token that guards every mutating route.

Being on localhost is not access control: any local process, or a web page that tricks the browser,
can reach 127.0.0.1. So changing anything needs a token made at startup. It is written to a
git-ignored file for the dashboard to read and is never logged.
"""

import secrets
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import structlog
from fastapi import Depends, Header, HTTPException, Request, Response
from pydantic import SecretStr

from promptshield.api.state import AppState, get_state
from promptshield.config import Settings

logger = structlog.get_logger(__name__)

TOKEN_HEADER = "X-Admin-Token"
COOKIE_NAME = "promptshield_admin"
TOKEN_BYTES = 32


def admin_token(settings: Settings) -> SecretStr:
    """The configured token if there is one, else a fresh one written to `admin_token_path`."""
    if settings.admin_token is not None:
        return settings.admin_token
    token = secrets.token_urlsafe(TOKEN_BYTES)
    _write_private(settings.admin_token_path, token)
    logger.info("admin_token_written", path=str(settings.admin_token_path))
    return SecretStr(token)


def _write_private(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)  # on Windows this only clears read-only; the folder is the user's own


def require_admin(
    request: Request,
    state: Annotated[AppState, Depends(get_state)],
    token: Annotated[str | None, Header(alias=TOKEN_HEADER)] = None,
) -> None:
    """The header (dev proxy, scripts) or the dashboard's cookie. Constant-time comparison, so
    timing can't reveal the token a character at a time."""
    expected = state.admin_token.get_secret_value()
    if token is None and _same_origin(request):
        token = request.cookies.get(COOKIE_NAME)
    if token is None or not secrets.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="admin token missing or wrong")


def _same_origin(request: Request) -> bool:
    """The cookie only counts for requests from the dashboard's own page. It is SameSite=Strict,
    so browsers don't send it from other sites anyway; this is a second check."""
    origin = request.headers.get("origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("host")


def set_admin_cookie(response: Response, token: SecretStr) -> None:
    """For the dashboard served by the API itself (installed package): HttpOnly, so page scripts
    can't read it, and Strict, so no other site can make the browser send it."""
    response.set_cookie(
        COOKIE_NAME,
        token.get_secret_value(),
        httponly=True,
        samesite="strict",
        path="/",
    )
