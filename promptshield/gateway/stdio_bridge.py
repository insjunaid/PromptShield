"""For MCP clients that only speak stdio: forwards everything to the gateway in the API.

    uv run python -m promptshield.gateway.stdio_bridge --task "Summarize my inbox"

Nothing is checked here. The API's gateway checks every call, keeps the events, and holds the
approvals, so all of it shows on the dashboard whichever way the client connects.

The bridge answers the client at once and connects to the gateway in the background: an app
gives up on an MCP server that doesn't answer quickly, and the shield may still be starting. A
tool request waits for that connection (up to `wait_seconds`); a dropped connection is retried, so
a restarted shield is picked up again.
"""

import argparse
import asyncio
from collections.abc import Sequence
from typing import Any

import anyio
import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from promptshield.config import get_settings
from promptshield.gateway.protocol import SERVER_NAME, TASK_HEADER

CONNECT_TIMEOUT_SECONDS = 30.0
READ_TIMEOUT_SECONDS = 600.0
WAIT_SECONDS = 120.0  # how long a tool request waits for the shield to come up
RETRY_SECONDS = 0.5
NOT_READY = "PromptShield isn't running yet. Start it with `uvx promptshield-mcp start`."


class Upstream:
    """The gateway session, once connected. Handlers wait for it instead of failing at once."""

    def __init__(self, wait_seconds: float = WAIT_SECONDS) -> None:
        self.wait_seconds = wait_seconds
        self.session: ClientSession | None = None
        self.ready = asyncio.Event()

    async def get(self) -> ClientSession | None:
        try:
            await asyncio.wait_for(self.ready.wait(), self.wait_seconds)
        except TimeoutError:
            return None
        return self.session

    async def keep_connected(self, url: str, headers: dict[str, str]) -> None:
        # A long read timeout: a call waiting for human approval can take minutes.
        timeout = httpx.Timeout(CONNECT_TIMEOUT_SECONDS, read=READ_TIMEOUT_SECONDS)
        while True:
            try:
                async with (
                    httpx.AsyncClient(
                        headers=headers, timeout=timeout, follow_redirects=True, trust_env=False
                    ) as http,
                    streamable_http_client(url, http_client=http) as (read, write, _),
                    ClientSession(read, write) as session,
                ):
                    await session.initialize()
                    self.session = session
                    self.ready.set()
                    await anyio.sleep_forever()
            except Exception:  # noqa: BLE001 - the shield isn't up yet, or went away: try again
                self.ready.clear()
                self.session = None
                await anyio.sleep(RETRY_SECONDS)


def bridge_server(upstream: Upstream) -> Server[Any, Any]:
    server: Server[Any, Any] = Server(SERVER_NAME)

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        session = await upstream.get()
        return [] if session is None else (await session.list_tools()).tools

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        session = await upstream.get()
        if session is None:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=NOT_READY)], isError=True
            )
        return await session.call_tool(name, arguments or {})

    return server


async def run(url: str, task: str | None, wait_seconds: float = WAIT_SECONDS) -> None:
    headers = {TASK_HEADER: task} if task else {}
    upstream = Upstream(wait_seconds)
    async with anyio.create_task_group() as group:
        group.start_soon(upstream.keep_connected, url, headers)
        server = bridge_server(upstream)
        async with stdio_server() as (stdin, stdout):
            await server.run(stdin, stdout, server.create_initialization_options())
        group.cancel_scope.cancel()  # the client went away: stop reconnecting


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Bridge a stdio MCP client to PromptShield.")
    parser.add_argument("--url", default=f"http://{settings.host}:{settings.api_port}/mcp/")
    parser.add_argument("--task", default=None, help="The user's task, if known.")
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    asyncio.run(run(args.url, args.task))


if __name__ == "__main__":
    main()
