"""The gateway as an MCP server, served over streamable HTTP inside the API process.

Living in the API process means events reach the dashboard live and approvals are answered in the
same place. Clients that only speak stdio use `stdio_bridge`, which forwards to this server.

Each MCP connection is its own session. A client may send the user's task, either as the
`X-PromptShield-Task` header or in a call's `_meta`, so the judge and task alignment can use it.
"""

from collections.abc import AsyncIterator, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any
from weakref import WeakKeyDictionary

import structlog
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import Receive, Scope, Send

from promptshield.config import UpstreamServer
from promptshield.gateway.core import Gateway, Upstream
from promptshield.models import new_id

logger = structlog.get_logger(__name__)

SERVER_NAME = "promptshield-gateway"
TASK_HEADER = "x-promptshield-task"
TASK_META_KEY = "promptshield/user_task"
MAX_TASK_CHARS = 2000
LOCAL_HOSTS = ["127.0.0.1:*", "localhost:*"]


def _user_task(meta: Any, request: Any) -> str | None:
    task = getattr(meta, TASK_META_KEY, None) if meta is not None else None
    if task is None and meta is not None and hasattr(meta, "model_extra"):
        task = (meta.model_extra or {}).get(TASK_META_KEY)
    if task is None and request is not None:
        task = request.headers.get(TASK_HEADER)
    return str(task)[:MAX_TASK_CHARS] if task else None


def build_server(gateway: Gateway, session_id: str | None = None) -> Server[Any, Any]:
    """`session_id` pins every connection to one session, for in-process use such as the lab,
    where the agent's own steps are logged under that id too."""
    server: Server[Any, Any] = Server(SERVER_NAME)
    session_ids: WeakKeyDictionary[Any, str] = WeakKeyDictionary()

    def session_of(context: Any) -> str:
        if context.session not in session_ids:
            session_ids[context.session] = session_id or new_id()
        return session_ids[context.session]

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        return await gateway.list_tools(session_of(server.request_context))

    # Upstream servers validate their own input, so the gateway doesn't second-guess it.
    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        context = server.request_context
        task = _user_task(context.meta, context.request)
        return await gateway.call_tool(session_of(context), name, arguments, task)

    return server


class MountedGateway:
    """Mounted when the app is built, attached once the gateway exists. Until then it answers
    503, so a client can't reach the tools before they are guarded."""

    def __init__(self) -> None:
        self._target: HttpGateway | None = None

    def attach(self, target: "HttpGateway | None") -> None:
        self._target = target

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._target is None:
            await send({"type": "http.response.start", "status": 503, "headers": []})
            await send({"type": "http.response.body", "body": b"gateway not ready"})
            return
        await self._target(scope, receive, send)


class HttpGateway:
    """The streamable HTTP endpoint. `run()` must wrap the app's lifetime."""

    def __init__(self, server: Server[Any, Any]) -> None:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=LOCAL_HOSTS,
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
        )
        self._manager = StreamableHTTPSessionManager(app=server, security_settings=security)

    def run(self) -> Any:
        return self._manager.run()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._manager.handle_request(scope, receive, send)


@asynccontextmanager
async def connect_upstreams(
    servers: Sequence[UpstreamServer],
) -> AsyncIterator[dict[str, Upstream]]:
    """Starts each configured tool server over stdio. One that fails to start is logged and left
    out, so the rest still work; its tools simply don't appear."""
    connected: dict[str, Upstream] = {}
    async with AsyncExitStack() as stack:
        for upstream in servers:
            try:
                params = StdioServerParameters(command=upstream.command, args=upstream.args)
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                connected[upstream.name] = session
            except Exception as error:
                logger.error(
                    "upstream_start_failed", upstream=upstream.name, error=type(error).__name__
                )
        yield connected
