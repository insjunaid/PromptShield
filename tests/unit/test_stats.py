"""Dashboard KPIs come straight from recorded events."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from ulid import ULID

from promptshield.models import (
    Approval,
    Decision,
    Direction,
    Event,
    Finding,
    LayerName,
    Severity,
    ToolCall,
    Verdict,
)
from promptshield.redact import Redactor
from promptshield.stats import compute_stats
from promptshield.storage.db import Database

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "stats.db", Redactor())
    yield db
    db.close()


def finding(layer: LayerName, rule: str) -> Finding:
    return Finding(
        layer=layer,
        rule_id=rule,
        title="t",
        severity=Severity.HIGH,
        score=0.9,  # type: ignore[arg-type]
        evidence="x",
        latency_ms=1,
    )


def save(
    database: Database,
    when: datetime,
    decision: Decision | None = Decision.ALLOW,
    kind: str = "verdict",
    findings: list[Finding] | None = None,
    latency: float = 100.0,
) -> None:
    verdict = (
        Verdict(
            decision=decision, risk_score=0.5, findings=findings or [], total_latency_ms=latency
        )
        if decision is not None
        else None
    )
    database.add_event(
        Event(
            id=str(ULID.from_datetime(when)),
            ts=when,
            session_id="s1",
            type=kind,  # type: ignore[arg-type]
            direction=Direction.INBOUND,
            verdict=verdict,
        )
    )


def test_an_empty_database_gives_zeros(database: Database) -> None:
    stats = compute_stats(database, "1h", NOW)
    assert (stats.scans, stats.blocked, stats.sanitized, stats.p95_ms) == (0, 0, 0, 0.0)
    assert len(stats.series) == 12


def test_decisions_are_counted(database: Database) -> None:
    for decision in (Decision.ALLOW, Decision.BLOCK, Decision.BLOCK, Decision.SANITIZE):
        save(database, NOW - timedelta(minutes=5), decision)
    stats = compute_stats(database, "1h", NOW)
    assert (stats.scans, stats.blocked, stats.sanitized) == (4, 2, 1)


def test_the_window_leaves_out_older_events(database: Database) -> None:
    save(database, NOW - timedelta(minutes=10), Decision.BLOCK)
    save(database, NOW - timedelta(hours=3), Decision.BLOCK)
    assert compute_stats(database, "1h", NOW).blocked == 1
    assert compute_stats(database, "24h", NOW).blocked == 2
    assert compute_stats(database, "all", NOW).blocked == 2


def test_tool_call_verdicts_count_as_scans(database: Database) -> None:
    save(database, NOW - timedelta(minutes=1), Decision.BLOCK, kind="tool_call")
    assert compute_stats(database, "1h", NOW).blocked == 1


def test_latency_uses_result_scans_only(database: Database) -> None:
    for latency in (100, 200, 300, 400, 1000):
        save(database, NOW - timedelta(minutes=2), latency=latency)
    save(database, NOW - timedelta(minutes=2), kind="tool_call", latency=99_999)
    stats = compute_stats(database, "1h", NOW)
    assert stats.p50_ms == 300
    assert stats.p95_ms == 1000


def test_detections_count_only_verdicts_that_acted(database: Database) -> None:
    save(database, NOW - timedelta(minutes=3), Decision.BLOCK, findings=[finding("L2", "L2.CSS.x")])
    save(database, NOW - timedelta(minutes=3), Decision.ALLOW, findings=[finding("L0", "L0.y")])
    stats = compute_stats(database, "1h", NOW)
    assert stats.findings_by_layer == {"L2": 1}
    assert stats.top_rules == {"L2.CSS.x": 1}


def test_canary_trips_are_counted(database: Database) -> None:
    save(database, NOW - timedelta(minutes=4), Decision.BLOCK, kind="canary_tripped")
    assert compute_stats(database, "1h", NOW).canaries_tripped == 1


def test_pending_approvals_are_counted_whatever_the_window(database: Database) -> None:
    call = ToolCall(session_id="s1", server="http", tool="http_post", args={})
    database.save_approval(
        Approval(
            session_id="s1",
            tool_call=call,
            reasons=["x"],
            created=NOW,
            expires=NOW + timedelta(minutes=2),
        )
    )
    assert compute_stats(database, "1h", NOW).approvals_pending == 1


def test_the_series_puts_events_in_their_slice(database: Database) -> None:
    save(database, NOW - timedelta(minutes=58), Decision.BLOCK)  # first 5-minute slice
    save(database, NOW - timedelta(minutes=1), Decision.BLOCK)
    series = compute_stats(database, "1h", NOW).series
    assert series[0].blocked == 1
    assert series[-1].blocked == 1
    assert sum(bucket.blocked for bucket in series) == 2
