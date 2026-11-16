"""Latency stats, size buckets, the judge sample and the report. No models: the runner is
smoke-run instead."""

import json
from pathlib import Path

from eval import latency
from eval.run_benchmark import judge_sample
from eval.scan_suite import ScanItem


def test_stats_use_measured_values_only() -> None:
    result = latency.stats([10.0, 20.0, 30.0, 40.0, 1000.0])
    assert (result.n, result.p50, result.p95, result.p99, result.max) == (
        5,
        30.0,
        1000.0,
        1000.0,
        1000.0,
    )
    assert result.mean == 220.0
    assert latency.stats([]).n == 0


def test_size_buckets_cover_every_length() -> None:
    assert latency.size_bucket(0) == "< 500 chars"
    assert latency.size_bucket(499) == "< 500 chars"
    assert latency.size_bucket(500) == "500-2000 chars"
    assert latency.size_bucket(2000) == "> 2000 chars"


def item(index: int, attack: bool) -> ScanItem:
    return ScanItem(id=f"i{index}", dataset="lab", text="x", attack=attack, source="web")


def test_the_judge_sample_is_balanced_and_stable() -> None:
    items = [item(i, attack=i % 3 == 0) for i in range(30)]
    sample = judge_sample(items, 6)
    assert [s.attack for s in sample] == [True, True, True, False, False, False]
    assert sample == judge_sample(items, 6)


def sample(ms: float, *, chars: int = 100, judged: bool = False, **layers: float) -> latency.Sample:
    return latency.Sample(
        id="s", dataset="lab", chars=chars, ms=ms, judged=judged, layers_ms=layers
    )


def path(name: str, judge_mode: str, samples: list[latency.Sample]) -> latency.PathResult:
    return latency.PathResult(
        name=name,
        label=f"{name} path",
        layers=["L0"],
        judge_mode=judge_mode,
        classifier=None,
        cold_start_s=4.2,
        rounds=1,
        samples=samples,
    )


def report(fast_ms: float) -> latency.LatencyReport:
    fast = path(
        "fast",
        "off",
        [sample(fast_ms, L0=2.0, L1=fast_ms - 10), sample(fast_ms, chars=3000, L0=3.0)],
    )
    timed_out = sample(50_000.0, judged=True)
    timed_out.judge_failed = True
    deployed = path("deployed", "uncertain", [sample(90.0), sample(9000.0, judged=True), timed_out])
    guard = latency.GuardResult(
        rounds=2,
        by_call={"read_file": latency.stats([3.0, 4.0])},
        all_calls=latency.stats([3.0, 4.0]),
    )
    return latency.LatencyReport(
        stamp="20261116_1000",
        git="abc1234",
        machine="test machine",
        power="on mains power",
        judge_model="qwen3:4b-instruct",
        classifier_threshold=0.10,
        task_alignment=False,
        items={"lab": 2},
        paths=[fast, deployed],
        guard=guard,
    )


def test_the_report_states_the_target_and_splits_judged_items() -> None:
    text = latency.markdown(report(80.0), "chart.png")
    assert "Fast path p50 80 ms: meets the target of 150 ms" in text
    assert "|   of which judged | 2 | 9.0 s |" in text
    assert "counted in the judged rows: 1 in deployed path." in text
    assert "| Layer | n |" in text and "| Item size | n |" in text
    assert "|   of which not judged | 1 | 90 ms |" in text
    assert "| L1 | 1 | 70 ms |" in text
    assert "| > 2000 chars | 1 |" in text
    assert "on mains power" in text
    assert "misses" in latency.markdown(report(400.0), None)


def test_writing_makes_markdown_json_and_a_chart(tmp_path: Path) -> None:
    written = latency.write(report(80.0), tmp_path)
    assert written.name == "latency_20261116_1000.md"
    assert (tmp_path / "latency_20261116_1000.png").stat().st_size > 0
    data = json.loads((tmp_path / "latency_20261116_1000.json").read_text(encoding="utf-8"))
    assert [p["name"] for p in data["paths"]] == ["fast", "deployed"]


def test_guard_calls_cover_reads_and_egress() -> None:
    names = {call.tool for call in latency.guard_calls(9999)}
    assert names == {"read_file", "list_files", "http_post", "send_email"}
