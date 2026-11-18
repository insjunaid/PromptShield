"""Serves the built dashboard from the API itself, for the installed package.

In development the dashboard runs on Vite (port 5173) and its proxy adds the admin token. An
installed copy has no Node: the built files ship in `promptshield/web/`, and the API serves them on
its own port. The page gets the admin token as an HttpOnly, SameSite=Strict cookie, so its own
requests are authorized and nothing else can use it (auth.py).
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response

from promptshield.api.auth import set_admin_cookie
from promptshield.api.state import AppState
from promptshield.config import PACKAGE_DIR

WEB_DIR = PACKAGE_DIR / "web"
INDEX = "index.html"
# Paths the API owns. An unknown one is a real 404, not the dashboard's page.
API_PREFIXES = ("v1/", "mcp", "health", "docs", "redoc", "openapi.json")


def dashboard_built(folder: Path = WEB_DIR) -> bool:
    return (folder / INDEX).is_file()


def mount_dashboard(app: FastAPI, folder: Path = WEB_DIR) -> None:
    """Registered last, so every API route and the gateway are matched first."""
    root = folder.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    async def dashboard(path: str, request: Request) -> Response:
        if path.startswith(API_PREFIXES):
            raise HTTPException(status_code=404, detail="not found")
        target = (root / path).resolve()
        # A file inside the build folder is served as is; anything else is a page of the app.
        if path and target.is_relative_to(root) and target.is_file():
            return FileResponse(target)
        page = FileResponse(root / INDEX, headers={"Cache-Control": "no-store"})
        state: AppState = request.app.state.shield
        set_admin_cookie(page, state.admin_token)
        return page
