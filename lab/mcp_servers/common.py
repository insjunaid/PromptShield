"""Shared safety checks for the mock servers."""

import os
from pathlib import Path
from urllib.parse import urlsplit

from lab.fixtures.runs import RunPaths
from promptshield.policy.destinations import LOCALHOST, Endpoint, parse_url

RUN_DIR_ENV = "PROMPTSHIELD_RUN_DIR"
LOOPBACK_ADDRESS = "127.0.0.1"
REQUEST_TIMEOUT_SECONDS = 10.0


def paths_from_env() -> RunPaths:
    """Each server process serves one run, named by the lab runner."""
    value = os.environ.get(RUN_DIR_ENV)
    if not value:
        raise RuntimeError(f"{RUN_DIR_ENV} is not set")
    return RunPaths(Path(value))


def require_local_url(url: str, port: int, tool: str) -> str:
    """Return a safe URL for this exact local port, or refuse.

    The URL is rebuilt rather than reused, so aliases and embedded credentials go no further.
    """
    if parse_url(url) != Endpoint(LOCALHOST, port):
        raise ValueError(f"{tool} refused this URL: only local port {port} is allowed")
    parts = urlsplit(url.strip())
    query = f"?{parts.query}" if parts.query else ""
    return f"http://{LOOPBACK_ADDRESS}:{port}{parts.path or '/'}{query}"
