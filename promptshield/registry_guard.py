"""Registry guard: the tools themselves are an attack surface.

A tool's name, description and argument descriptions are read by the model, so a malicious server
can hide orders there ("tool poisoning"). A server can also behave until trusted and then change its
tools ("rug pull"), or offer a tool that imitates or steers another server's ("shadowing").

Clean tools are pinned on first sight (trust on first use). A poisoned tool is quarantined: hidden
from the agent and never pinned automatically. A changed definition is hidden until a human approves
it. If the scan itself fails, the tool is quarantined, so a broken scanner can't wave tools through.
"""

import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field

import structlog
from mcp import types

from promptshield.events import EventBus
from promptshield.layers.base import ScanContext
from promptshield.models import (
    ContentItem,
    Decision,
    Event,
    Finding,
    SessionInfo,
    Severity,
    ToolPin,
    ToolStatus,
)
from promptshield.pipeline import ContentPipeline
from promptshield.policy.engine import PolicyEngine
from promptshield.storage.db import Database

logger = structlog.get_logger(__name__)

POISONED_RULE = "REGISTRY.poisoned"
RUG_PULL_RULE = "REGISTRY.rug_pull"
# A look-alike name is flagged. Naming another server's tool is held back: steering another
# server's tools is the documented shadowing attack, and a description has little reason to.
LOOKALIKE_RULE = "REGISTRY.shadowing_name"
MENTION_RULE = "REGISTRY.shadowing_mention"
HOLD_BACK_RULES = frozenset({"REGISTRY.poisoned", "REGISTRY.scan_failed", MENTION_RULE})
SCAN_FAILED_RULE = "REGISTRY.scan_failed"
VISIBLE: frozenset[ToolStatus] = frozenset({"trusted", "flagged"})
# Only names that look like tool names count as mentions, so "search" or "email" in ordinary
# prose don't read as one server steering another's tools.
TOOL_LIKE_NAME = re.compile(r"[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)+")
NOT_ALPHANUMERIC = re.compile(r"[^a-z0-9]")


@dataclass
class ReviewedTool:
    server: str
    tool: types.Tool
    sha256: str
    status: ToolStatus
    findings: list[Finding] = field(default_factory=list)

    @property
    def visible(self) -> bool:
        return self.status in VISIBLE


def fingerprint(tool: types.Tool) -> str:
    """Everything the model reads about a tool, in a stable order."""
    definition = {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.inputSchema,
        "annotations": tool.annotations.model_dump() if tool.annotations else None,
    }
    canonical = json.dumps(definition, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _schema_text(schema: object) -> Iterator[str]:
    """Property names and every description, however deeply nested."""
    stack = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "description" and isinstance(value, str):
                    yield value
                elif key == "properties" and isinstance(value, dict):
                    yield from (str(name) for name in value)
                    stack.extend(value.values())
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def readable_text(tool: types.Tool) -> str:
    parts = [f"Tool name: {tool.name}", tool.title or "", tool.description or ""]
    parts.extend(_schema_text(tool.inputSchema))
    return "\n".join(part for part in parts if part)


def _squeeze(name: str) -> str:
    return NOT_ALPHANUMERIC.sub("", name.lower())


def _finding(rule_id: str, title: str, severity: Severity, evidence: str) -> Finding:
    return Finding(
        layer="REGISTRY",
        rule_id=rule_id,
        title=title,
        severity=severity,
        score=1.0,
        evidence=evidence,
        latency_ms=0,
    )


def shadowing(
    server: str, tool: types.Tool, catalogue: Mapping[str, Sequence[types.Tool]]
) -> list[Finding]:
    """A look-alike of another server's tool, or a description that names one."""
    findings: list[Finding] = []
    text = readable_text(tool)
    for other_server, others in catalogue.items():
        if other_server == server:
            continue
        for other in others:
            if _squeeze(other.name) == _squeeze(tool.name):
                findings.append(
                    _finding(
                        LOOKALIKE_RULE,
                        "Imitates another server's tool",
                        Severity.HIGH,
                        f"{server}.{tool.name} looks like {other_server}.{other.name}",
                    )
                )
            elif TOOL_LIKE_NAME.fullmatch(other.name) and re.search(
                rf"(?<![\w-]){re.escape(other.name)}(?![\w-])", text
            ):
                findings.append(
                    _finding(
                        MENTION_RULE,
                        "Refers to another server's tool",
                        Severity.HIGH,
                        f"{server}.{tool.name} mentions {other_server}.{other.name}",
                    )
                )
    return findings


class RegistryGuard:
    def __init__(
        self,
        pipeline: ContentPipeline,
        engine: PolicyEngine,
        database: Database,
        bus: EventBus,
        *,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled  # off only for the ablation (P7.3): every tool passes unreviewed
        self._pipeline = pipeline
        self._engine = engine
        self._database = database
        self._bus = bus
        self._scans: dict[str, list[Finding]] = {}  # definition hash -> poisoning findings
        self._current: dict[tuple[str, str], ReviewedTool] = {}

    def current(self) -> list[ReviewedTool]:
        return list(self._current.values())

    async def review(
        self, catalogue: Mapping[str, Sequence[types.Tool]], session_id: str | None = None
    ) -> dict[str, list[types.Tool]]:
        """Every server's tools, reviewed. Returns only the tools the agent may see. With a
        session, the tools hidden from it are recorded on that session too, so what the registry
        guard stopped shows in the session's timeline."""
        if not self._enabled:
            return {server: list(tools) for server, tools in catalogue.items()}
        visible: dict[str, list[types.Tool]] = {}
        hidden: list[ReviewedTool] = []
        for server, tools in catalogue.items():
            visible[server] = []
            for tool in tools:
                reviewed = await self._review_one(server, tool, catalogue)
                self._current[(server, tool.name)] = reviewed
                if reviewed.visible:
                    visible[server].append(tool)
                else:
                    hidden.append(reviewed)
        if session_id is not None and hidden:
            await self._hidden_from_session(session_id, hidden)
        return visible

    async def _hidden_from_session(self, session_id: str, hidden: list[ReviewedTool]) -> None:
        rules = sorted({finding.rule_id for item in hidden for finding in item.findings})
        await self._bus.publish(
            Event(
                session_id=session_id,
                type="registry_alert",
                payload={
                    "status": "hidden",
                    "tools": [f"{item.server}.{item.tool.name}" for item in hidden],
                    "rules": rules,
                },
            )
        )

    def approve(self, server: str, tool_name: str) -> ToolPin | None:
        """A human trusts the current definition. It is pinned, whatever the scan said."""
        reviewed = self._current.get((server, tool_name))
        if reviewed is None:
            return None
        pin = ToolPin(server=server, tool=tool_name, sha256=reviewed.sha256, status="trusted")
        self._database.save_pin(pin)
        reviewed.status = "trusted"
        return pin

    async def _review_one(
        self, server: str, tool: types.Tool, catalogue: Mapping[str, Sequence[types.Tool]]
    ) -> ReviewedTool:
        sha = fingerprint(tool)
        pin = self._database.get_pin(server, tool.name)
        if pin is not None and pin.sha256 == sha and pin.status == "trusted":
            return ReviewedTool(server, tool, sha, "trusted")  # a human or first sight trusted it
        if pin is not None and pin.sha256 != sha:
            return await self._rug_pull(server, tool, sha, pin)
        findings = [*await self._poisoning(server, tool, sha), *shadowing(server, tool, catalogue)]
        if pin is not None:
            return ReviewedTool(server, tool, sha, pin.status, findings)  # waiting for a human
        return await self._first_sight(server, tool, sha, findings)

    async def _first_sight(
        self, server: str, tool: types.Tool, sha: str, findings: list[Finding]
    ) -> ReviewedTool:
        held = any(item.rule_id in HOLD_BACK_RULES for item in findings)
        status: ToolStatus = "quarantined" if held else "flagged" if findings else "trusted"
        self._database.save_pin(ToolPin(server=server, tool=tool.name, sha256=sha, status=status))
        if findings:
            await self._alert(server, tool.name, status, findings)
        return ReviewedTool(server, tool, sha, status, findings)

    async def _rug_pull(
        self, server: str, tool: types.Tool, sha: str, pin: ToolPin
    ) -> ReviewedTool:
        """The pin keeps the old hash, so approving is what accepts the new definition."""
        finding = _finding(
            RUG_PULL_RULE,
            "A tool changed after it was trusted",
            Severity.CRITICAL,
            f"{server}.{tool.name} changed from {pin.sha256[:12]} to {sha[:12]}",
        )
        self._database.save_pin(pin.model_copy(update={"status": "quarantined"}))
        await self._alert(server, tool.name, "quarantined", [finding])
        return ReviewedTool(server, tool, sha, "quarantined", [finding])

    async def _poisoning(self, server: str, tool: types.Tool, sha: str) -> list[Finding]:
        if sha in self._scans:
            return self._scans[sha]
        source = f"registry:{server}.{tool.name}"
        try:
            item = ContentItem(kind="text", data=readable_text(tool), source=source)
            result = await self._pipeline.scan(ScanContext(session=SessionInfo(), items=[item]))
            verdict = self._engine.decide_inbound(result)
        except Exception as error:
            logger.error("registry_scan_failed", tool=source, error=type(error).__name__)
            return [_finding(SCAN_FAILED_RULE, "Tool could not be checked", Severity.HIGH, source)]
        findings: list[Finding] = []
        if verdict.decision is not Decision.ALLOW:
            evidence = "; ".join(verdict.reasons[:3])
            findings.append(
                _finding(
                    POISONED_RULE,
                    "Tool description holds instructions",
                    Severity.CRITICAL,
                    f"{source}: {evidence}",
                )
            )
        self._scans[sha] = findings
        return findings

    async def _alert(
        self, server: str, tool_name: str, status: ToolStatus, findings: list[Finding]
    ) -> None:
        await self._bus.publish(
            Event(
                type="registry_alert",
                tool=f"{server}.{tool_name}",
                payload={
                    "status": status,
                    "rules": [item.rule_id for item in findings],
                    "evidence": [item.evidence for item in findings],
                },
            )
        )
