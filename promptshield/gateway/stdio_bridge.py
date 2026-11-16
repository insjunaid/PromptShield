"""For MCP clients that only speak stdio: forwards everything to the gateway in the API.

    uv run python -m promptshield.gateway.stdio_bridge --task "Summarize my inbox"

Nothing is checked here. The API's gateway checks every call, keeps the events, and holds the
approvals, so all of it shows on the dashboard whichever way the client connects.
"""

import argparse
import asyncio
from collections.abc import Sequence
from typing import Any

import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from promptshield.config import get_settings
from promptshield.gateway.server import SERVER_NAME, TASK_HEADER

CONNECT_TIMEOUT_SECONDS = 30.0
READ_TIMEOUT_SECONDS = 600.0


def bridge_server(upstream: ClientSession) -> Server[Any, Any]:
    server: Server[Any, Any] = Server(SERVER_NAME)

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        return (await upstream.list_tools()).tools

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        return await upstream.call_tool(name, arguments or {})

    return server


async def run(url: str, task: str | None) -> None:
    headers = {TASK_HEADER: task} if task else {}
    # A long read timeout: a call waiting for human approval can take minutes.
    timeout = httpx.Timeout(CONNECT_TIMEOUT_SECONDS, read=READ_TIMEOUT_SECONDS)
    async with (
        httpx.AsyncClient(
            headers=headers, timeout=timeout, follow_redirects=True, trust_env=False
        ) as http,
        streamable_http_client(url, http_client=http) as (read, write, _),
        ClientSession(read, write) as upstream,
    ):
        await upstream.initialize()
        server = bridge_server(upstream)
        async with stdio_server() as (stdin, stdout):
            await server.run(stdin, stdout, server.create_initialization_options())


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
