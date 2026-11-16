"""The gateway's logic, separate from any transport.

For each tool call: the action guard runs first, and a blocked call never reaches the tool. An
allowed call goes upstream, and its result is scanned before the agent sees it, error results
included, because an injection can sit in an error message. Every result is recorded as untrusted
in the session, and as sensitive when the tool returns private data.

Anything that fails while checking a result returns a block message, never the raw result.
"""

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import structlog
from mcp import types

from promptshield.approvals import ApprovalQueue
from promptshield.events import EventBus
from promptshield.layers.base import ScanContext
from promptshield.layers.l4_action_guard import ActionGuard
from promptshield.models import (
    AutoApprove,
    ContentItem,
    Decision,
    Direction,
    Event,
    SessionInfo,
    ToolCall,
    Verdict,
)
from promptshield.policy.engine import PolicyEngine, block_message
from promptshield.registry_guard import RegistryGuard
from promptshield.sessions import SessionStore
from promptshield.shield import Shield
from promptshield.storage.db import Database

logger = structlog.get_logger(__name__)

CANARY_RULE = "CANARY.tripped"
UPSTREAM_FAILED = "The tool failed to respond."
CHECK_FAILED = "PromptShield could not check this result, so it was withheld."


class Upstream(Protocol):
    """The part of an MCP client session the gateway uses, so tests can stand one in."""

    async def list_tools(self) -> types.ListToolsResult: ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult: ...


@dataclass
class GatewayServices:
    engine: PolicyEngine
    guard: ActionGuard
    approvals: ApprovalQueue
    shield: Shield
    sessions: SessionStore
    bus: EventBus
    database: Database
    registry: RegistryGuard | None = None  # None only in tests that don't exercise it


def blocked_call_message(verdict: Verdict) -> str:
    """What the agent sees. Our reasons only: never the arguments, which may hold secrets."""
    reasons = "; ".join(verdict.reasons[:3])
    return f"Tool call blocked by PromptShield: {reasons}"


def _error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=True)


def to_items(result: types.CallToolResult, source: str) -> list[ContentItem]:
    """Every block is scanned. Types without text of their own are scanned as JSON, so nothing
    passes unread just because it has an unusual shape."""
    items: list[ContentItem] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            items.append(ContentItem(kind="text", data=block.text, source=source))
        elif isinstance(block, types.ImageContent):
            items.append(
                ContentItem(
                    kind="image",
                    data=block.data,
                    data_is_base64=True,
                    source=source,
                    mime=block.mimeType,
                )
            )
        else:
            items.append(ContentItem(kind="json", data=block.model_dump_json(), source=source))
    if result.structuredContent is not None:
        items.append(
            ContentItem(kind="json", data=json.dumps(result.structuredContent), source=source)
        )
    if not items:
        items.append(ContentItem(kind="text", data="", source=source))
    return items


def to_content(items: list[ContentItem]) -> list[types.ContentBlock]:
    blocks: list[types.ContentBlock] = []
    for item in items:
        if item.kind == "image":
            blocks.append(
                types.ImageContent(type="image", data=item.data, mimeType=item.mime or "image/png")
            )
        else:
            blocks.append(types.TextContent(type="text", text=item.data))
    return blocks


class Gateway:
    def __init__(
        self,
        services: GatewayServices,
        upstreams: Mapping[str, Upstream],
        auto_approve: AutoApprove | None = None,
        call_timeout_seconds: float = 120.0,
    ) -> None:
        """`auto_approve` is set by whoever runs the gateway, such as the lab runner. A client
        can't set it, so a client can't approve its own calls."""
        self._services = services
        self._upstreams = dict(upstreams)
        self._auto_approve = auto_approve
        self._timeout = call_timeout_seconds
        self._routes: dict[str, str] = {}  # exposed tool name -> upstream name
        self._tools: list[types.Tool] = []

    @property
    def routes(self) -> dict[str, str]:
        return dict(self._routes)

    async def refresh_tools(self, session_id: str | None = None) -> list[types.Tool]:
        """Collects every upstream's tools and lets the registry guard hide poisoned or changed
        ones. A name offered twice keeps the first; the registry guard reports the shadowing."""
        catalogue: dict[str, list[types.Tool]] = {}
        for upstream_name, upstream in self._upstreams.items():
            catalogue[upstream_name] = list((await upstream.list_tools()).tools)
        registry = self._services.registry
        visible = (
            await registry.review(catalogue, session_id) if registry is not None else catalogue
        )
        routes: dict[str, str] = {}
        tools: list[types.Tool] = []
        for upstream_name, offered in visible.items():
            for tool in offered:
                if tool.name in routes:
                    logger.warning("tool_name_taken", tool=tool.name, upstream=upstream_name)
                    continue
                routes[tool.name] = upstream_name
                # The gateway may rewrite a result, which drops its structured content, so it can't
                # promise an output schema. Clients reject a sanitized result that breaks one.
                tools.append(tool.model_copy(update={"outputSchema": None}))
        self._routes, self._tools = routes, tools
        return tools

    async def list_tools(self, session_id: str | None = None) -> list[types.Tool]:
        """Re-lists every time, so a tool that changed since the last session is seen at once."""
        return await self.refresh_tools(session_id)

    async def call_tool(
        self,
        session_id: str,
        name: str,
        arguments: dict[str, Any] | None,
        user_task: str | None = None,
    ) -> types.CallToolResult:
        if not self._routes:
            await self.refresh_tools()
        upstream_name = self._routes.get(name)
        if upstream_name is None:
            return _error_result(f"Unknown tool: {name}")
        session = await self._session(session_id, user_task)
        call = ToolCall(
            session_id=session_id, tool=name, server=upstream_name, args=arguments or {}
        )
        refusal = await self._refusal(call, session)
        if refusal is not None:
            return refusal
        result = await self._forward(upstream_name, call)
        return await self._checked(call, session, result)

    # Before the call

    async def _refusal(self, call: ToolCall, session: SessionInfo) -> types.CallToolResult | None:
        """None if the call may go ahead, else the result to give the agent instead."""
        services = self._services
        verdict = await services.guard.evaluate(call, session.user_task)
        await self._publish(call, "tool_call", Direction.OUTBOUND, verdict, {"args": call.args})
        if any(finding.rule_id == CANARY_RULE for finding in verdict.findings):
            await self._publish(call, "canary_tripped", Direction.OUTBOUND, verdict, {})
        if verdict.decision is Decision.ALLOW:
            return None
        if verdict.decision is Decision.REQUIRE_APPROVAL:
            auto = self._auto_approve or session.auto_approve
            if await services.approvals.request(call, verdict, auto):
                return None
            return _error_result(
                "Tool call blocked by PromptShield: it needed approval and was not approved."
            )
        return _error_result(blocked_call_message(verdict))

    async def _forward(self, upstream_name: str, call: ToolCall) -> types.CallToolResult:
        try:
            return await asyncio.wait_for(
                self._upstreams[upstream_name].call_tool(call.tool, call.args),
                timeout=self._timeout,
            )
        except Exception as error:
            logger.error("upstream_failed", upstream=upstream_name, error=type(error).__name__)
            return _error_result(UPSTREAM_FAILED)

    # After the call

    async def _checked(
        self, call: ToolCall, session: SessionInfo, result: types.CallToolResult
    ) -> types.CallToolResult:
        services = self._services
        source = f"{call.server}.{call.tool}"
        items = to_items(result, source)
        try:
            ctx = ScanContext(session=session, items=items)
            verdict = await services.shield.inspect(ctx)
        except Exception as error:
            logger.error("result_check_failed", error=type(error).__name__)
            return _error_result(CHECK_FAILED)
        services.sessions.get(call.session_id).record_result(
            source,
            [item.data for item in items if item.kind != "image"],
            verdict.findings,
            sensitive=services.engine.has_sensitive_output(call),
        )
        await self._publish(call, "verdict", Direction.INBOUND, verdict, {"sources": [source]})
        if verdict.decision is Decision.ALLOW:
            return result
        if verdict.decision is Decision.SANITIZE and verdict.sanitized_items is not None:
            return types.CallToolResult(
                content=to_content(verdict.sanitized_items), isError=result.isError
            )
        return _error_result(block_message(verdict))

    # Shared

    async def _session(self, session_id: str, user_task: str | None) -> SessionInfo:
        """Storage trouble must not stop a call, so it falls back to a fresh session."""
        database = self._services.database
        try:
            known = await asyncio.to_thread(database.get_session, session_id)
            if known is not None:
                return known
            session = SessionInfo(id=session_id, user_task=user_task)
            await asyncio.to_thread(database.save_session, session)
            await self._services.bus.publish(Event(session_id=session_id, type="session_start"))
            return session
        except Exception as error:
            logger.error("session_storage_failed", error=type(error).__name__)
            return SessionInfo(id=session_id, user_task=user_task)

    async def _publish(
        self,
        call: ToolCall,
        kind: str,
        direction: Direction,
        verdict: Verdict,
        payload: dict[str, Any],
    ) -> None:
        await self._services.bus.publish(
            Event(
                session_id=call.session_id,
                type=kind,  # type: ignore[arg-type]
                direction=direction,
                tool=f"{call.server}.{call.tool}",
                verdict=verdict,
                payload=payload,
            )
        )
