"""The admin token that guards every mutating route.

Being on localhost is not access control: any local process, or a web page that tricks the browser,
can reach 127.0.0.1. So changing anything needs a token made at startup. It is written to a
git-ignored file for the dashboard to read and is never logged.
"""

import secrets
from pathlib import Path
from typing import Annotated

import structlog
from fastapi import Depends, Header, HTTPException
from pydantic import SecretStr

from promptshield.api.state import AppState, get_state
from promptshield.config import Settings

logger = structlog.get_logger(__name__)

TOKEN_HEADER = "X-Admin-Token"
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
    state: Annotated[AppState, Depends(get_state)],
    token: Annotated[str | None, Header(alias=TOKEN_HEADER)] = None,
) -> None:
    """Constant-time comparison, so timing can't reveal the token a character at a time."""
    expected = state.admin_token.get_secret_value()
    if token is None or not secrets.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="admin token missing or wrong")
