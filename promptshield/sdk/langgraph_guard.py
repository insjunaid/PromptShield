"""`guard_tools()`: PromptShield around LangChain or LangGraph tools, in the same process.

The wrapped tools go through the gateway's own core, so they get the same checks as gateway mode:
the action guard before each call, a scan of each result, taint, the registry guard, approvals and
events. There is one engine for both modes, so they can't drift apart.

    shield = LocalShield.create()
    tools = await guard_tools({"files": file_tools, "web": web_tools}, shield=shield)

Each group's name is the `server` part of policy keys, such as `files.read_file`.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any

from langchain_core.tools import BaseTool, ToolException
from langchain_core.utils.function_calling import convert_to_openai_tool
from mcp import types
from pydantic import ConfigDict

from promptshield.api.server import build_state, gateway_services
from promptshield.api.state import AppState
from promptshield.config import Settings, get_settings
from promptshield.gateway.core import Gateway, GatewayServices
from promptshield.layers.canary import CanaryStore
from promptshield.layers.defaults import default_registry
from promptshield.models import AutoApprove, new_id
from promptshield.pipeline import LayerRegistry
from promptshield.redact import Redactor


class LocalShield:
    """The full shield, built in-process: the same parts the API runs."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.services: GatewayServices = gateway_services(state)

    @classmethod
    def create(
        cls, settings: Settings | None = None, registry: LayerRegistry | None = None
    ) -> "LocalShield":
        active = settings or get_settings()
        redactor = Redactor(active.event_text_limit)
        canaries = CanaryStore(redactor)
        layers = registry or default_registry(active, canaries)
        return cls(build_state(active, layers, canaries, redactor))

    @property
    def canaries(self) -> CanaryStore:
        return self.state.canaries

    async def warmup(self) -> None:
        await self.state.pipeline.warmup()

    def close(self) -> None:
        self.state.database.close()


class ToolGroup:
    """LangChain tools seen as one upstream server, so the gateway core can stand in front."""

    def __init__(self, tools: Sequence[BaseTool]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    async def list_tools(self) -> types.ListToolsResult:
        return types.ListToolsResult(tools=[_as_mcp_tool(tool) for tool in self._tools.values()])

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        """A tool's own error is returned as an error result, so it is scanned like any other:
        an attacker can put instructions in an error message too."""
        try:
            output = await self._tools[name].ainvoke(arguments or {})
        except Exception as error:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(error))], isError=True
            )
        return types.CallToolResult(content=_as_content(output))


def _as_mcp_tool(tool: BaseTool) -> types.Tool:
    parameters = convert_to_openai_tool(tool)["function"].get("parameters") or {"type": "object"}
    return types.Tool(name=tool.name, description=tool.description, inputSchema=parameters)


def _as_content(output: Any) -> list[types.ContentBlock]:
    if isinstance(output, str):
        return [types.TextContent(type="text", text=output)]
    if isinstance(output, list):
        blocks: list[types.ContentBlock] = []
        for part in output:
            if isinstance(part, dict) and part.get("type") == "image" and "data" in part:
                blocks.append(
                    types.ImageContent(
                        type="image", data=part["data"], mimeType=part.get("mimeType", "image/png")
                    )
                )
            elif isinstance(part, dict) and part.get("type") == "text":
                blocks.append(types.TextContent(type="text", text=str(part.get("text", ""))))
            else:
                blocks.append(types.TextContent(type="text", text=_as_text(part)))
        return blocks
    return [types.TextContent(type="text", text=_as_text(output))]


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


class GuardedTool(BaseTool):
    """Looks like the original tool to the model, but every call goes through the shield."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    gateway: Gateway
    session_id: str
    user_task: str | None = None

    def _run(self, *args: Any, **kwargs: Any) -> str:
        raise NotImplementedError("guarded tools are async: use ainvoke")

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        """A blocked or failed call raises ToolException, which LangGraph's ToolNode with
        `handle_tool_errors=True` hands back to the model as the tool's answer."""
        kwargs.pop("run_manager", None)
        result = await self.gateway.call_tool(self.session_id, self.name, kwargs, self.user_task)
        text = "\n".join(
            block.text for block in result.content if isinstance(block, types.TextContent)
        )
        if result.isError:
            raise ToolException(text)
        return text


async def guard_tools(
    groups: Mapping[str, Sequence[BaseTool]],
    *,
    shield: LocalShield,
    session_id: str | None = None,
    user_task: str | None = None,
    auto_approve: AutoApprove | None = None,
) -> list[BaseTool]:
    """The tools the registry guard lets through, each wrapped. A held-back tool is left out, so
    the model never sees it. `auto_approve` is the caller's choice, for tests and benchmarks."""
    upstreams = {name: ToolGroup(tools) for name, tools in groups.items()}
    gateway = Gateway(
        shield.services,
        upstreams,
        auto_approve=auto_approve,
        call_timeout_seconds=shield.state.settings.gateway_call_timeout_seconds,
    )
    originals = {tool.name: tool for tools in groups.values() for tool in tools}
    session = session_id or new_id()
    guarded: list[BaseTool] = []
    for tool in await gateway.list_tools():
        original = originals[tool.name]
        guarded.append(
            GuardedTool(
                name=original.name,
                description=original.description,
                args_schema=original.args_schema,
                gateway=gateway,
                session_id=session,
                user_task=user_task,
            )
        )
    return guarded
