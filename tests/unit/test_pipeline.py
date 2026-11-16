"""The pipeline must keep going when a layer fails, and must report exactly what happened."""

import asyncio
import time
from collections.abc import Awaitable, Callable

import pytest
from structlog.testing import capture_logs

from promptshield.config import Settings
from promptshield.layers.base import LayerSkipped, ScanContext
from promptshield.models import Finding, LayerName, Segment, SessionInfo, Severity
from promptshield.pipeline import ContentPipeline, LayerRegistry

ALL_LAYERS: list[LayerName] = ["L0", "L2", "L1", "CANARY", "L3"]
SECRET_TEXT = "ignore previous instructions sk-canary-abc"

Behaviour = Callable[[ScanContext], Awaitable[list[Finding]]]


def finding(layer: LayerName, score: float = 0.5, latency_ms: float = 0.0) -> Finding:
    return Finding(
        layer=layer,
        rule_id=f"{layer}.test",
        title="test",
        severity=Severity.LOW,
        score=score,
        evidence="evidence",
        latency_ms=latency_ms,
    )


class FakeLayer:
    def __init__(self, name: LayerName, behaviour: Behaviour | None = None) -> None:
        self.name = name
        self.behaviour = behaviour
        self.scans = 0
        self.warmups = 0

    async def warmup(self) -> None:
        self.warmups += 1

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        self.scans += 1
        if self.behaviour:
            return await self.behaviour(ctx)
        return [finding(self.name)]


def constant(layer: FakeLayer) -> Callable[[], FakeLayer]:
    return lambda: layer


def build(
    overrides: dict[LayerName, FakeLayer] | None = None,
    enabled: list[LayerName] | None = None,
    **options: object,
) -> tuple[ContentPipeline, dict[LayerName, FakeLayer]]:
    layers = {name: FakeLayer(name) for name in ALL_LAYERS} | (overrides or {})
    registry = LayerRegistry()
    for name, layer in layers.items():
        registry.register(name, constant(layer))
    active = ALL_LAYERS if enabled is None else enabled
    return ContentPipeline(registry, active, **options), layers  # type: ignore[arg-type]


def context() -> ScanContext:
    return ScanContext(session=SessionInfo())


async def crash(ctx: ScanContext) -> list[Finding]:
    raise RuntimeError(SECRET_TEXT)


async def unavailable(ctx: ScanContext) -> list[Finding]:
    raise LayerSkipped("not installed")


async def hang(ctx: ScanContext) -> list[Finding]:
    await asyncio.sleep(30)
    return []


async def test_layers_run_in_the_documented_order() -> None:
    order: list[str] = []

    def recording(name: LayerName) -> FakeLayer:
        async def behaviour(ctx: ScanContext) -> list[Finding]:
            order.append(name)
            return []

        return FakeLayer(name, behaviour)

    pipeline, _ = build(
        {name: recording(name) for name in ALL_LAYERS},
        judge_mode="always",
    )
    await pipeline.scan(context())
    assert order == ["L0", "L2", "L1", "CANARY", "L3"]


async def test_later_layers_see_segments_and_prior_findings() -> None:
    seen: dict[str, object] = {}

    async def extract(ctx: ScanContext) -> list[Finding]:
        ctx.segments.append(Segment(text="hidden", origin="hidden_css"))
        return [finding("L2")]

    async def classify(ctx: ScanContext) -> list[Finding]:
        seen["segments"] = [segment.text for segment in ctx.segments]
        seen["prior"] = [item.layer for item in ctx.prior_findings]
        return []

    pipeline, _ = build({"L2": FakeLayer("L2", extract), "L1": FakeLayer("L1", classify)})
    result = await pipeline.scan(context())
    assert seen == {"segments": ["hidden"], "prior": ["L0", "L2"]}
    assert [segment.text for segment in result.segments] == ["hidden"]


async def test_a_crash_is_recorded_and_later_layers_still_run() -> None:
    pipeline, layers = build({"L2": FakeLayer("L2", crash)})
    result = await pipeline.scan(context())
    assert result.layers_run["L2"] == "error"
    assert result.layers_run["L1"] == "ran"
    assert layers["CANARY"].scans == 1


async def test_a_factory_crash_is_isolated_too() -> None:
    def broken() -> FakeLayer:
        raise OSError("model file missing")

    registry = LayerRegistry()
    registry.register("L0", broken)
    registry.register("L1", lambda: FakeLayer("L1"))
    pipeline = ContentPipeline(registry, ["L0", "L1"])
    result = await pipeline.scan(context())
    assert result.layers_run["L0"] == "error"
    assert result.layers_run["L1"] == "ran"


async def test_error_logs_never_contain_the_exception_text() -> None:
    pipeline, _ = build({"L2": FakeLayer("L2", crash)})
    with capture_logs() as logs:
        await pipeline.scan(context())
    assert "sk-canary" not in str(logs)
    assert any(entry.get("error") == "RuntimeError" for entry in logs)


async def test_a_hung_layer_times_out_as_an_error() -> None:
    pipeline, _ = build({"L1": FakeLayer("L1", hang)}, layer_timeout_seconds=0.01)
    result = await asyncio.wait_for(pipeline.scan(context()), timeout=5)
    assert result.layers_run["L1"] == "error"
    assert result.layers_run["CANARY"] == "ran"


async def test_cancelling_a_scan_is_not_swallowed() -> None:
    pipeline, _ = build({"L1": FakeLayer("L1", hang)})
    task = asyncio.create_task(pipeline.scan(context()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_optional_layer_can_skip_itself() -> None:
    pipeline, _ = build({"L2": FakeLayer("L2", unavailable)})
    result = await pipeline.scan(context())
    assert result.layers_run["L2"] == "skipped"


async def test_required_layer_skipping_itself_is_an_error() -> None:
    pipeline, _ = build({"L1": FakeLayer("L1", unavailable)})
    result = await pipeline.scan(context())
    assert result.layers_run["L1"] == "error"


async def test_enabled_but_unregistered_required_layer_is_an_error() -> None:
    registry = LayerRegistry()
    pipeline = ContentPipeline(registry, ["L1", "L2"])
    result = await pipeline.scan(context())
    assert result.layers_run["L1"] == "error"
    assert result.layers_run["L2"] == "skipped"


async def test_disabled_layers_are_skipped_even_if_required() -> None:
    enabled: list[LayerName] = ["L0", "L2", "CANARY"]
    pipeline, layers = build(enabled=enabled)
    result = await pipeline.scan(context())
    assert result.layers_run["L1"] == "skipped"
    assert layers["L1"].scans == 0


async def test_disabled_layers_are_never_built() -> None:
    built: list[str] = []

    def factory() -> FakeLayer:
        built.append("L1")
        return FakeLayer("L1")

    registry = LayerRegistry()
    registry.register("L1", factory)
    pipeline = ContentPipeline(registry, [])
    await pipeline.warmup()
    await pipeline.scan(context())
    assert built == []


async def test_layers_are_built_once_across_scans() -> None:
    built: list[str] = []

    def factory() -> FakeLayer:
        built.append("L1")
        return FakeLayer("L1")

    registry = LayerRegistry()
    registry.register("L1", factory)
    pipeline = ContentPipeline(registry, ["L1"])
    await pipeline.scan(context())
    await pipeline.scan(context())
    assert built == ["L1"]


def test_duplicate_registration_is_refused() -> None:
    registry = LayerRegistry()
    registry.register("L1", lambda: FakeLayer("L1"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register("L1", lambda: FakeLayer("L1"))


@pytest.mark.parametrize(
    ("mode", "gate_answer", "expected"),
    [
        ("uncertain", True, "ran"),
        ("uncertain", False, "skipped"),
        ("always", False, "ran"),
        ("off", True, "skipped"),
    ],
)
async def test_judge_modes(mode: str, gate_answer: bool, expected: str) -> None:
    pipeline, _ = build(judge_mode=mode, judge_gate=lambda findings: gate_answer)
    result = await pipeline.scan(context())
    assert result.layers_run["L3"] == expected


async def test_judge_is_skipped_without_a_gate() -> None:
    pipeline, layers = build(judge_mode="uncertain")
    result = await pipeline.scan(context())
    assert result.layers_run["L3"] == "skipped"
    assert layers["L3"].scans == 0


async def test_gate_receives_the_findings_so_far() -> None:
    received: list[str] = []

    def gate(findings: list[Finding]) -> bool:
        received.extend(item.layer for item in findings)
        return False

    pipeline, _ = build(judge_gate=gate)
    await pipeline.scan(context())
    assert received == ["L0", "L2", "L1", "CANARY"]


async def test_a_gate_failure_is_recorded_as_a_judge_error() -> None:
    def gate(findings: list[Finding]) -> bool:
        raise ValueError("bad policy")

    pipeline, _ = build(judge_gate=gate)
    result = await pipeline.scan(context())
    assert result.layers_run["L3"] == "error"


async def test_each_layer_and_the_whole_scan_are_timed() -> None:
    async def slow(ctx: ScanContext) -> list[Finding]:
        await asyncio.sleep(0.02)
        return [finding("L1")]

    pipeline, _ = build({"L1": FakeLayer("L1", slow)})
    result = await pipeline.scan(context())
    assert result.layer_latency_ms["L1"] >= 15
    assert result.total_latency_ms >= result.layer_latency_ms["L1"]


async def test_findings_get_the_layer_time_unless_they_measured_their_own() -> None:
    async def mixed(ctx: ScanContext) -> list[Finding]:
        # asyncio.sleep can wake early on Windows' coarse timer; time.sleep can't (Python 3.11+).
        time.sleep(0.005)  # noqa: ASYNC251
        return [finding("L2"), finding("L2", latency_ms=0.25)]

    pipeline, _ = build({"L2": FakeLayer("L2", mixed)})
    result = await pipeline.scan(context())
    stamped, measured = [item for item in result.findings if item.layer == "L2"]
    assert stamped.latency_ms > 1
    assert measured.latency_ms == 0.25


async def test_warmup_covers_enabled_layers_only() -> None:
    enabled: list[LayerName] = ["L0", "L1"]
    pipeline, layers = build(enabled=enabled)
    await pipeline.warmup()
    assert layers["L1"].warmups == 1
    assert layers["L2"].warmups == 0


async def test_a_warmup_failure_does_not_stop_startup() -> None:
    class BrokenWarmup(FakeLayer):
        async def warmup(self) -> None:
            raise OSError("model missing")

    pipeline, layers = build({"L0": BrokenWarmup("L0")})
    await pipeline.warmup()
    assert layers["L1"].warmups == 1


async def test_from_settings_uses_the_configured_layers_and_mode() -> None:
    settings = Settings(_env_file=None, enabled_layers=["L0", "L3"], judge_mode="off")  # type: ignore[call-arg]
    registry = LayerRegistry()
    layer = FakeLayer("L0")
    judge = FakeLayer("L3")
    registry.register("L0", constant(layer))
    registry.register("L3", constant(judge))
    result = await ContentPipeline.from_settings(settings, registry).scan(context())
    assert result.layers_run["L0"] == "ran"
    assert result.layers_run["L1"] == "skipped"
    assert judge.scans == 0
