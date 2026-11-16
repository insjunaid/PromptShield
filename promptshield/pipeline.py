"""Runs the content layers in order and collects what they found.

The pipeline gathers evidence and the policy engine turns it into a decision. The one crossing point
is the judge: L3 is slow, so it runs only when the policy's gate says the risk is uncertain.
"""

import asyncio
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from time import perf_counter
from typing import Literal, Self

import structlog
from pydantic import Field

from promptshield.config import Settings
from promptshield.layers.base import Layer, LayerSkipped, ScanContext
from promptshield.models import Finding, LayerName, LayerStatus, Schema, Segment

logger = structlog.get_logger(__name__)

# L2 comes before L1 because L1 must also classify what L2 extracts.
CONTENT_ORDER: tuple[LayerName, ...] = ("L0", "L2", "L1", "CANARY")
JUDGE_LAYER: LayerName = "L3"

# Running without these would look clean while checking nothing, so absence counts as an error.
REQUIRED_LAYERS: frozenset[LayerName] = frozenset({"L1"})

JudgeMode = Literal["off", "uncertain", "always"]
JudgeGate = Callable[[list[Finding]], bool]
LayerFactory = Callable[[], Layer]


class PipelineResult(Schema):
    findings: list[Finding] = Field(default_factory=list)
    segments: list[Segment] = Field(default_factory=list)
    layers_run: dict[str, LayerStatus] = Field(default_factory=dict)
    layer_latency_ms: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = Field(default=0.0, ge=0)


class LayerRegistry:
    """Builds each layer on first use and keeps it, so disabled models never reach memory."""

    def __init__(self) -> None:
        self._factories: dict[LayerName, LayerFactory] = {}
        self._built: dict[LayerName, Layer] = {}

    def register(self, name: LayerName, factory: LayerFactory) -> None:
        if name in self._factories:
            raise ValueError(f"layer {name} is already registered")
        self._factories[name] = factory

    def __contains__(self, name: object) -> bool:
        return name in self._factories

    def get(self, name: LayerName) -> Layer:
        if name not in self._built:
            self._built[name] = self._factories[name]()
        return self._built[name]


@dataclass
class _Run:
    """Results of one scan, while it's in progress."""

    findings: list[Finding] = field(default_factory=list)
    statuses: dict[str, LayerStatus] = field(default_factory=dict)
    latencies: dict[str, float] = field(default_factory=dict)


class ContentPipeline:
    def __init__(
        self,
        registry: LayerRegistry,
        enabled: Collection[LayerName],
        *,
        judge_mode: JudgeMode = "uncertain",
        judge_gate: JudgeGate | None = None,
        layer_timeout_seconds: float = 60.0,
    ) -> None:
        self._registry = registry
        self._enabled = frozenset(enabled)
        self._judge_mode = judge_mode
        self._judge_gate = judge_gate
        self._timeout = layer_timeout_seconds

    @classmethod
    def from_settings(
        cls, settings: Settings, registry: LayerRegistry, judge_gate: JudgeGate | None = None
    ) -> Self:
        return cls(
            registry,
            settings.enabled_layers,
            judge_mode=settings.judge_mode,
            judge_gate=judge_gate,
            layer_timeout_seconds=settings.layer_timeout_seconds,
        )

    async def warmup(self) -> None:
        """Warm every enabled layer. A failure here surfaces on the first scan, not at startup."""
        for name in self._active_layers((*CONTENT_ORDER, JUDGE_LAYER)):
            try:
                await self._registry.get(name).warmup()
            except Exception as error:
                logger.warning("layer_warmup_failed", layer=name, error=type(error).__name__)

    async def scan(self, ctx: ScanContext) -> PipelineResult:
        """Run the layers. Never raises for a layer failure: it's recorded for the policy."""
        started = perf_counter()
        run = _Run()
        for name in CONTENT_ORDER:
            await self._run_layer(name, ctx, run)
        await self._maybe_run_judge(ctx, run)
        return PipelineResult(
            findings=run.findings,
            segments=ctx.segments,
            layers_run=run.statuses,
            layer_latency_ms=run.latencies,
            total_latency_ms=(perf_counter() - started) * 1000,
        )

    def _active_layers(self, names: Iterable[LayerName]) -> list[LayerName]:
        return [name for name in names if name in self._enabled and name in self._registry]

    async def _maybe_run_judge(self, ctx: ScanContext, run: _Run) -> None:
        if JUDGE_LAYER not in self._enabled or self._judge_mode == "off":
            run.statuses[JUDGE_LAYER] = "skipped"
            return
        try:
            wanted = self._judge_mode == "always" or (
                self._judge_gate is not None and self._judge_gate(run.findings)
            )
        except Exception as error:
            logger.error("judge_gate_failed", error=type(error).__name__)
            run.statuses[JUDGE_LAYER] = "error"
            return
        if wanted:
            await self._run_layer(JUDGE_LAYER, ctx, run)
        else:
            run.statuses[JUDGE_LAYER] = "skipped"

    async def _run_layer(self, name: LayerName, ctx: ScanContext, run: _Run) -> None:
        if name not in self._enabled:
            run.statuses[name] = "skipped"
            return
        if name not in self._registry:
            self._record_absent(name, run)
            return

        started = perf_counter()
        try:
            layer = self._registry.get(name)
            findings = await asyncio.wait_for(layer.scan(ctx), timeout=self._timeout)
        except LayerSkipped:
            self._record_absent(name, run)
        except Exception as error:
            # Only the type: exception text can quote attacker content or secrets.
            logger.error("layer_failed", layer=name, error=type(error).__name__)
            run.statuses[name] = "error"
        else:
            elapsed_ms = (perf_counter() - started) * 1000
            stamped = [_with_latency(finding, elapsed_ms) for finding in findings]
            run.findings.extend(stamped)
            ctx.prior_findings.extend(stamped)
            run.statuses[name] = "ran"
        run.latencies[name] = (perf_counter() - started) * 1000

    @staticmethod
    def _record_absent(name: LayerName, run: _Run) -> None:
        status: LayerStatus = "error" if name in REQUIRED_LAYERS else "skipped"
        logger.warning("layer_unavailable", layer=name, status=status)
        run.statuses[name] = status


def _with_latency(finding: Finding, elapsed_ms: float) -> Finding:
    """Use the layer's time for findings that didn't measure their own."""
    if finding.latency_ms > 0:
        return finding
    return finding.model_copy(update={"latency_ms": elapsed_ms})
