"""Latency profiling (P7.4): what the shield adds per tool call, fast path vs judge path.

Every request goes through the real app in-process (FastAPI TestClient, no network), so the time
includes the pipeline, the policy, redaction and the event write, which is what a tool call waits
for in gateway mode. The per-layer split comes from the pipeline's own timings on the same items.
Model loading happens once at startup and is reported apart as the cold start.
"""

import gc
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from time import perf_counter
from typing import Any, Literal

from fastapi.testclient import TestClient

from eval.metrics import percentile
from eval.scan_report import INK, MUTED, SERIES, _style
from eval.scan_suite import BASE_URL, PG2_22M, PG2_86M, TASK, ScanConfig, ScanItem, settings_for
from promptshield.api.server import create_app
from promptshield.layers.base import ScanContext
from promptshield.models import ContentItem, LayerName, Schema, SessionInfo

FAST_LAYERS: list[LayerName] = ["L0", "L2", "L1", "CANARY"]
JUDGE_LAYERS: list[LayerName] = [*FAST_LAYERS, "L3"]
TARGET_P50_MS = 150.0  # CONTEXT.md: fast path p50 under about 150 ms on CPU
SIZE_BUCKETS = (
    (0, 500, "< 500 chars"),
    (500, 2000, "500-2000 chars"),
    (2000, None, "> 2000 chars"),
)


class Stats(Schema):
    n: int
    p50: float
    p95: float
    p99: float
    mean: float
    max: float


def stats(values: Sequence[float]) -> Stats:
    """Nearest-rank percentiles, so every number reported was actually measured."""
    if not values:
        return Stats(n=0, p50=0.0, p95=0.0, p99=0.0, mean=0.0, max=0.0)
    return Stats(
        n=len(values),
        p50=percentile(values, 0.50),
        p95=percentile(values, 0.95),
        p99=percentile(values, 0.99),
        mean=sum(values) / len(values),
        max=max(values),
    )


def size_bucket(chars: int) -> str:
    for low, high, label in SIZE_BUCKETS:
        if chars >= low and (high is None or chars < high):
            return label
    raise AssertionError("unreachable")


class Sample(Schema):
    id: str
    dataset: str
    chars: int
    ms: float  # end to end through /v1/scan or /v1/guard/tool-call
    judged: bool = False  # the judge was called (it answered or failed)
    judge_failed: bool = False  # the call failed, e.g. timed out (the policy then fails closed)
    layers_ms: dict[str, float] = {}  # from the pipeline's own timing (fast path only)


class PathResult(Schema):
    name: str
    label: str
    layers: list[str]
    judge_mode: str
    classifier: str | None
    cold_start_s: float  # app startup with model loading, before the first request
    rounds: int
    samples: list[Sample]

    def total(self) -> Stats:
        return stats([sample.ms for sample in self.samples])

    def judged(self) -> Stats:
        return stats([sample.ms for sample in self.samples if sample.judged])

    def not_judged(self) -> Stats:
        return stats([sample.ms for sample in self.samples if not sample.judged])

    def judge_failures(self) -> int:
        return sum(sample.judge_failed for sample in self.samples)

    def by_layer(self) -> dict[str, Stats]:
        names = sorted({name for sample in self.samples for name in sample.layers_ms})
        return {
            name: stats([s.layers_ms[name] for s in self.samples if name in s.layers_ms])
            for name in names
        }

    def by_size(self) -> dict[str, Stats]:
        out: dict[str, Stats] = {}
        for _, _, label in SIZE_BUCKETS:
            values = [s.ms for s in self.samples if size_bucket(s.chars) == label]
            if values:
                out[label] = stats(values)
        return out


class GuardCall(Schema):
    name: str
    server: str
    tool: str
    args: dict[str, Any]


def guard_calls(sink_port: int) -> list[GuardCall]:
    """Typical calls from the lab: reads, a known-safe fetch, and egress L4 has to judge."""
    sink = f"http://127.0.0.1:{sink_port}/collect"
    return [
        GuardCall(name="read_file", server="files", tool="read_file", args={"path": "notes.txt"}),
        GuardCall(name="list_files", server="files", tool="list_files", args={}),
        GuardCall(
            name="http_post to an unknown host",
            server="http",
            tool="http_post",
            args={"url": sink, "body": "meeting notes for Tuesday"},
        ),
        GuardCall(
            name="send_email to an outside address",
            server="mail",
            tool="send_email",
            args={"to": "someone@example.org", "subject": "Notes", "body": "See you Tuesday."},
        ),
    ]


class GuardResult(Schema):
    rounds: int
    by_call: dict[str, Stats]
    all_calls: Stats


class LatencyReport(Schema):
    stamp: str
    git: str
    machine: str
    power: str
    judge_model: str
    classifier_threshold: float
    task_alignment: bool
    items: dict[str, int]
    paths: list[PathResult]
    guard: GuardResult | None
    skipped: list[str] = []


Echo = Callable[[str], None]


def _context(item: ScanItem) -> ScanContext:
    return ScanContext(
        session=SessionInfo(user_task=TASK),
        items=[ContentItem(kind="text", data=item.text, source=item.source)],
    )


def run_path(
    config: ScanConfig,
    items: Sequence[ScanItem],
    rounds: int,
    echo: Echo,
    *,
    per_layer: bool,
    label: str,
) -> PathResult:
    """`rounds` passes over the items after one warm-up request. With `per_layer`, each item also
    goes through the pipeline directly once per round, for the per-layer split."""
    samples: list[Sample] = []
    with tempfile.TemporaryDirectory() as folder:
        settings = settings_for(config, Path(folder))
        started = perf_counter()
        with TestClient(create_app(settings), base_url=BASE_URL) as client:
            cold = perf_counter() - started
            payload = {"items": [{"kind": "text", "data": "warm-up", "source": "web"}]}
            client.post("/v1/scan", json=payload).raise_for_status()
            state = client.app.state.shield  # type: ignore[attr-defined]
            for round_index in range(rounds):
                for index, item in enumerate(items, start=1):
                    body = {
                        "items": [{"kind": "text", "data": item.text, "source": item.source}],
                        "user_task": TASK,
                    }
                    begun = perf_counter()
                    response = client.post("/v1/scan", json=body)
                    ms = (perf_counter() - begun) * 1000
                    response.raise_for_status()
                    judge_status = response.json()["layers_run"].get("L3")
                    layers: dict[str, float] = {}
                    if per_layer:
                        assert client.portal is not None
                        result = client.portal.call(state.pipeline.scan, _context(item))
                        layers = dict(result.layer_latency_ms)
                    samples.append(
                        Sample(
                            id=item.id,
                            dataset=item.dataset,
                            chars=len(item.text),
                            ms=ms,
                            judged=judge_status in ("ran", "error"),
                            judge_failed=judge_status == "error",
                            layers_ms=layers,
                        )
                    )
                    if index % 50 == 0 or index == len(items):
                        echo(f"  {config.name} round {round_index + 1}: {index}/{len(items)}")
    gc.collect()  # let the classifier go before the next path loads its own
    return PathResult(
        name=config.name,
        label=label,
        layers=list(config.layers),
        judge_mode=config.judge_mode,
        classifier=config.classifier_model,
        cold_start_s=cold,
        rounds=rounds,
        samples=samples,
    )


def run_guard(calls: Sequence[GuardCall], rounds: int, root: Path) -> GuardResult:
    """L4 alone on each call, `rounds` times, each in a fresh session so taint doesn't carry."""
    config = ScanConfig(name="guard", label="L4", layers=["L4"])
    settings = settings_for(config, root)
    times: dict[str, list[float]] = {call.name: [] for call in calls}
    with TestClient(create_app(settings), base_url=BASE_URL) as client:
        warm = {"session_id": "warm", "server": "files", "tool": "list_files", "args": {}}
        client.post("/v1/guard/tool-call", json=warm).raise_for_status()
        for round_index in range(rounds):
            for call in calls:
                body = {
                    "session_id": f"latency-{round_index}",
                    "server": call.server,
                    "tool": call.tool,
                    "args": call.args,
                }
                begun = perf_counter()
                client.post("/v1/guard/tool-call", json=body).raise_for_status()
                times[call.name].append((perf_counter() - begun) * 1000)
    every = [value for values in times.values() for value in values]
    return GuardResult(
        rounds=rounds,
        by_call={name: stats(values) for name, values in times.items()},
        all_calls=stats(every),
    )


PathName = Literal["fast", "fast-22m", "deployed", "judge"]


def path_configs() -> dict[PathName, tuple[ScanConfig, str]]:
    return {
        "fast": (
            ScanConfig(name="fast", label="fast", layers=FAST_LAYERS, classifier_model=PG2_86M),
            "Fast path: L0+L2+L1 (PG2-86M)+canary, judge off",
        ),
        "fast-22m": (
            ScanConfig(
                name="fast-22m", label="fast-22m", layers=FAST_LAYERS, classifier_model=PG2_22M
            ),
            "Fast path with PG2-22M (the low-latency option)",
        ),
        "deployed": (
            ScanConfig(
                name="deployed",
                label="deployed",
                layers=JUDGE_LAYERS,
                classifier_model=PG2_86M,
                judge_mode="uncertain",
            ),
            "As deployed: the judge only for uncertain items",
        ),
        "judge": (
            ScanConfig(
                name="judge",
                label="judge",
                layers=JUDGE_LAYERS,
                classifier_model=PG2_86M,
                judge_mode="always",
            ),
            "Judge path: the judge on every item (a sample)",
        ),
    }


# Report


def _ms(value: float) -> str:
    return f"{value / 1000:.1f} s" if value >= 1000 else f"{value:.0f} ms"


def _row(name: str, item: Stats) -> str:
    return (
        f"| {name} | {item.n} | {_ms(item.p50)} | {_ms(item.p95)} | {_ms(item.p99)} "
        f"| {_ms(item.max)} |"
    )


def header(first: str) -> list[str]:
    return [f"| {first} | n | p50 | p95 | p99 | max |", "| --- | --- | --- | --- | --- | --- |"]


HEADER = header("Path")


def headline(report: LatencyReport) -> list[str]:
    lines = list(HEADER)
    for path in report.paths:
        lines.append(_row(path.label, path.total()))
        if path.judge_mode == "uncertain":
            lines.append(_row("  of which judged", path.judged()))
            lines.append(_row("  of which not judged", path.not_judged()))
    failures = {path.label: path.judge_failures() for path in report.paths}
    failures = {label: count for label, count in failures.items() if count}
    if failures:
        lines.append("")
        lines += [
            f"Judge calls that failed (timed out or errored), counted in the judged rows: "
            f"{count} in {label}."
            for label, count in failures.items()
        ]
    if report.guard:
        lines.append(_row("L4 action guard (per tool call)", report.guard.all_calls))
    return lines


def verdict_line(report: LatencyReport) -> str:
    fast = next((path for path in report.paths if path.name == "fast"), None)
    if fast is None:
        return "The fast path wasn't measured."
    p50 = fast.total().p50
    met = "meets" if p50 <= TARGET_P50_MS else "misses"
    return (
        f"Fast path p50 {_ms(p50)}: {met} the target of {TARGET_P50_MS:.0f} ms (CONTEXT.md, CPU)."
    )


def markdown(report: LatencyReport, chart: str | None) -> str:
    r = report
    lines = [
        "# PromptShield Benchmark: latency",
        "",
        f"Run: {r.stamp}, git {r.git}, machine {r.machine}, {r.power}.",
        f"Judge {r.judge_model}, L1 threshold {r.classifier_threshold:.2f}, task alignment "
        f"{'on' if r.task_alignment else 'off'} (the default).",
        "Items: " + ", ".join(f"{name} {count}" for name, count in sorted(r.items.items())) + ".",
        "",
        "Each number is the time one request takes through the real app in-process (no network):",
        "pipeline, policy, redaction and the event write, which is what a tool call waits for in",
        "gateway mode. Model loading is reported apart as the cold start. One warm-up request",
        "per path is left out.",
        "",
        "## Headline: added latency per tool result",
        verdict_line(r),
        "",
        *headline(r),
    ]
    if chart:
        lines += ["", f"![p50 and p95 per path]({chart})"]
    fast = next((path for path in r.paths if path.name == "fast"), None)
    if fast:
        lines += ["", "## Fast path by layer (the pipeline's own timing)", *header("Layer")]
        lines += [_row(name, item) for name, item in fast.by_layer().items()]
        lines += ["", "## Fast path by item size", *header("Item size")]
        lines += [_row(name, item) for name, item in fast.by_size().items()]
    if r.guard:
        lines += ["", f"## L4 action guard, by call ({r.guard.rounds} rounds)", *header("Call")]
        lines += [_row(name, item) for name, item in r.guard.by_call.items()]
    lines += ["", "## Cold start (app startup including model loading)"]
    lines += [f"- {path.label}: {path.cold_start_s:.1f} s" for path in r.paths]
    if r.skipped:
        lines += ["", "## Not run", *[f"- {text}" for text in r.skipped]]
    lines += [
        "",
        "## Limitations",
        "- One laptop CPU, no GPU; another machine gives other numbers.",
        "- The judge path's time is almost all the local LLM; a GPU or a smaller judge changes it.",
        "- Task alignment (an LLM check in L4) is off by default and wasn't measured here.",
        "- In-process timing leaves out network hops between a remote client and the gateway.",
        "",
    ]
    return "\n".join(lines)


def chart(report: LatencyReport, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = [(item.label, item.total()) for item in report.paths]
    if report.guard:
        rows.append(("L4 action guard", report.guard.all_calls))
    names = [name for name, _ in rows]
    fig, ax = plt.subplots(figsize=(8, 0.6 * len(rows) + 1.6), dpi=150)
    height = 0.36
    for offset, key, colour, label in (
        (-height / 2, "p50", SERIES[0], "p50"),
        (height / 2, "p95", SERIES[1], "p95"),
    ):
        values = [max(getattr(item, key), 0.1) for _, item in rows]
        bars = ax.barh(
            [index + offset for index in range(len(rows))],
            values,
            height=height - 0.04,
            color=colour,
            label=label,
        )
        for bar, value in zip(bars, values, strict=True):
            ax.annotate(
                _ms(value),
                (bar.get_width(), bar.get_y() + bar.get_height() / 2),
                xytext=(4, 0),
                textcoords="offset points",
                va="center",
                color=INK,
                fontsize=8,
            )
    ax.axvline(TARGET_P50_MS, color=MUTED, linewidth=1, linestyle="--")
    ax.annotate(  # x in data units, y in axes units: bottom of the line, clear of the title
        f"{TARGET_P50_MS:.0f} ms target",
        (TARGET_P50_MS, 0.02),
        xycoords=("data", "axes fraction"),
        xytext=(4, 0),
        textcoords="offset points",
        va="bottom",
        color=MUTED,
        fontsize=8,
    )
    ax.set_xscale("log")
    ax.set_yticks(range(len(rows)), names, color=INK, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("added latency per call, ms (log scale)", color=MUTED)
    ax.set_title("Added latency per path", color=INK, fontsize=11, loc="left")
    legend = ax.legend(frameon=False, fontsize=8, loc="lower right")
    for text in legend.get_texts():
        text.set_color(MUTED)
    _style(ax)
    ax.grid(axis="x", color="#e3e6eb", linewidth=0.8)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)


def write(report: LatencyReport, folder: Path) -> Path:
    base = f"latency_{report.stamp}"
    chart(report, folder / f"{base}.png")
    (folder / f"{base}.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    path = folder / f"{base}.md"
    path.write_text(markdown(report, f"{base}.png"), encoding="utf-8")
    return path
