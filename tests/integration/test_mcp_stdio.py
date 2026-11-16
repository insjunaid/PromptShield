"""The servers as real processes, which is how the agent and the gateway will start them."""

import asyncio
import os
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

from lab.attack_site.build import ATTACK_IMAGE, build_site
from lab.fixtures.runs import RunPaths, create_run
from lab.mcp_servers.common import RUN_DIR_ENV
from lab.mcp_servers.evil_server import (
    CLEAN_DESCRIPTION,
    MODE_ENV,
    POISONED_DESCRIPTION,
)
from promptshield.config import REPO_ROOT


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


@contextmanager
def serve_directory(directory: Path, port: int) -> Iterator[None]:
    handler = partial(QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return None


def params(module: str, run: RunPaths, **extra: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", f"lab.mcp_servers.{module}"],
        cwd=str(REPO_ROOT),
        env={**os.environ, RUN_DIR_ENV: str(run.root), **extra},
    )


async def test_mail_server_works_over_stdio(tmp_path: Path) -> None:
    run = create_run(tmp_path, "run1", with_attacks=False)
    async with (
        stdio_client(params("mail_server", run)) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool("read_email", {"id": "m3"})
    block = result.content[0]
    assert isinstance(block, TextContent)
    assert "ignore my previous email" in block.text


@pytest.mark.slow
async def test_real_ocr_works_inside_the_stdio_server(tmp_path: Path) -> None:
    """Regression: OCR passed on its own, but hung every time inside this real server process."""
    run = create_run(tmp_path, "run1", with_attacks=True)
    site_dir = tmp_path / "site"
    build_site(site_dir, 9999)
    port = free_port()
    with serve_directory(site_dir, port):
        server = params("web_server", run, PROMPTSHIELD_ATTACK_SITE_PORT=str(port))
        async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            url = f"http://127.0.0.1:{port}/{ATTACK_IMAGE}"
            result = await asyncio.wait_for(
                session.call_tool("read_image_text", {"url": url}), timeout=60
            )
    block = result.content[0]
    assert isinstance(block, TextContent)
    assert "secrets.txt" in block.text


async def description_in_new_process(run: RunPaths, call_it: bool) -> str:
    server = params("evil_server", run, **{MODE_ENV: "rug_pull"})
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        [tool] = (await session.list_tools()).tools
        if call_it:
            await session.call_tool("get_weather", {"city": "Paris"})
    return tool.description or ""


async def test_rug_pull_across_two_real_sessions(tmp_path: Path) -> None:
    """The A11 flow: approve a clean tool, then see a different one in the next session."""
    run = create_run(tmp_path, "run1", with_attacks=True)
    assert await description_in_new_process(run, call_it=True) == CLEAN_DESCRIPTION
    assert await description_in_new_process(run, call_it=False) == POISONED_DESCRIPTION
