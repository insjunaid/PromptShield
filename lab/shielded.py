"""The victim agent's tools with PromptShield in front: `--shield on`.

The agent talks MCP to the gateway, and the gateway talks MCP to the run's own tool servers. Nothing
is shortcut: this is gateway mode, connected in memory instead of over HTTP so each run gets tool
servers pointed at its own sandbox.

Registry pins live in the run's folder. Shared pins would leak between runs: a weather tool pinned
clean in one run would turn the next A10 into a "rug pull", and a quarantine would carry over.
"""

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp.shared.memory import create_connected_server_and_client_session

from lab.agent.victim import LoadedTools, connection
from lab.fixtures.runs import RunPaths
from lab.scenario import Scenario
from promptshield.gateway.core import Gateway, Upstream
from promptshield.gateway.server import build_server
from promptshield.models import AutoApprove
from promptshield.redact import Redactor
from promptshield.registry_guard import RegistryGuard
from promptshield.sdk import LocalShield
from promptshield.storage.db import Database

PINS_FILE = "registry_pins.db"


@asynccontextmanager
async def open_shielded_tools(
    paths: RunPaths,
    scenario: Scenario,
    shield: LocalShield,
    session_id: str,
    auto_approve: AutoApprove | None,
) -> AsyncIterator[LoadedTools]:
    client = MultiServerMCPClient(
        {server: connection(server, paths, scenario.evil_mode) for server in scenario.servers}
    )
    async with AsyncExitStack() as stack:
        upstreams: dict[str, Upstream] = {
            server: await stack.enter_async_context(client.session(server))
            for server in scenario.servers
        }
        pins = Database(paths.root / PINS_FILE, Redactor())
        stack.callback(pins.close)
        state = shield.state
        registry = RegistryGuard(
            state.pipeline,
            state.engine,
            pins,
            state.bus,
            enabled="REGISTRY" in state.settings.enabled_layers,
        )
        gateway = Gateway(
            replace(shield.services, registry=registry),
            upstreams,
            auto_approve=auto_approve,
            call_timeout_seconds=state.settings.gateway_call_timeout_seconds,
        )
        agent_side = await stack.enter_async_context(
            create_connected_server_and_client_session(build_server(gateway, session_id))
        )
        tools = await load_mcp_tools(agent_side)
        routes = gateway.routes
        loaded = LoadedTools()
        for server in scenario.servers:
            loaded.add(server, [tool for tool in tools if routes.get(tool.name) == server])
        yield loaded
