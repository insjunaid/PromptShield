"""The interface every detection layer implements.

Layers never import each other. They share data through `ScanContext`, and shared services are
injected when a layer is built, so any layer can be switched off for ablation runs.
"""

from typing import Protocol

from pydantic import Field

from promptshield.models import (
    ContentItem,
    Finding,
    LayerName,
    Schema,
    Segment,
    SessionInfo,
    ToolCall,
)


class LayerSkipped(Exception):
    """Raised by a layer whose optional dependency is absent, such as OCR not being installed.

    This is different from a crash: a skip doesn't trigger the policy's `fail_mode`.
    """


class ScanContext(Schema):
    """Everything a layer may read. Earlier layers fill `segments` for later ones."""

    session: SessionInfo
    items: list[ContentItem] = Field(default_factory=list)  # inbound scans
    tool_call: ToolCall | None = None  # outbound scans (L4)
    segments: list[Segment] = Field(default_factory=list)
    prior_findings: list[Finding] = Field(default_factory=list)


class Layer(Protocol):
    name: LayerName

    async def warmup(self) -> None:
        """Load models once, so the first real scan isn't slow."""
        ...

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        """Inspect the context and return findings. May add to `ctx.segments`."""
        ...
