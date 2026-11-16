"""Dashboard KPIs, computed from stored events for a time window.

Event ids are ULIDs, whose first ten characters encode the creation time, so "events since T" is an
indexed comparison on the id. Everything comes from what was recorded: no number is estimated.
"""

from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlmodel import col, select
from ulid import ULID

from promptshield.models import Decision, Event, StatsBucket, StatsSnapshot
from promptshield.storage.db import Database, EventRow

StatsWindow = Literal["1h", "24h", "all"]
WINDOWS: dict[str, timedelta] = {"1h": timedelta(hours=1), "24h": timedelta(hours=24)}
TIME_PREFIX = 10  # ULID characters that hold the timestamp
BUCKETS = 12
TOP_RULES = 8
COUNTED_TYPES = ("verdict", "tool_call", "canary_tripped")


def _cutoff_id(since: datetime) -> str:
    """The smallest id a ULID made at `since` can have."""
    return str(ULID.from_datetime(since))[:TIME_PREFIX] + "0" * (26 - TIME_PREFIX)


def load_events(database: Database, since: datetime | None) -> list[Event]:
    query = select(EventRow).where(col(EventRow.type).in_(COUNTED_TYPES))
    if since is not None:
        query = query.where(col(EventRow.id) >= _cutoff_id(since))
    with database.session() as session:
        rows = session.exec(query.order_by(col(EventRow.seq))).all()
    return [Event.model_validate_json(row.data) for row in rows]


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _acted(event: Event) -> bool:
    return event.verdict is not None and event.verdict.decision is not Decision.ALLOW


def _buckets(events: Sequence[Event], start: datetime, end: datetime) -> list[StatsBucket]:
    """Even slices of the window, for sparklines. An empty slice is a zero, not a gap."""
    span = max((end - start) / BUCKETS, timedelta(seconds=1))
    buckets = [StatsBucket(start=start + span * index) for index in range(BUCKETS)]
    latencies: list[list[float]] = [[] for _ in buckets]
    for event in events:
        index = min(BUCKETS - 1, max(0, int((event.ts - start) / span)))
        bucket = buckets[index]
        if event.verdict is not None:
            bucket.scans += 1
            bucket.blocked += event.verdict.decision is Decision.BLOCK
            bucket.sanitized += event.verdict.decision is Decision.SANITIZE
            if event.type == "verdict":
                latencies[index].append(event.verdict.total_latency_ms)
    for bucket, values in zip(buckets, latencies, strict=True):
        bucket.p95_ms = _percentile(values, 0.95)
    return buckets


def compute_stats(
    database: Database, window: StatsWindow, now: datetime | None = None
) -> StatsSnapshot:
    end = now or datetime.now(UTC)
    since = end - WINDOWS[window] if window in WINDOWS else None
    events = load_events(database, since)
    verdicts = [event for event in events if event.verdict is not None]
    latencies = [e.verdict.total_latency_ms for e in verdicts if e.type == "verdict" and e.verdict]
    acted = [event for event in verdicts if _acted(event)]
    layers: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    for event in acted:
        assert event.verdict is not None
        layers.update(finding.layer for finding in event.verdict.findings)
        rules.update(finding.rule_id for finding in event.verdict.findings)
    start = since or (events[0].ts if events else end - timedelta(hours=1))
    return StatsSnapshot(
        window=window,
        scans=len(verdicts),
        blocked=sum(e.verdict.decision is Decision.BLOCK for e in verdicts if e.verdict),
        sanitized=sum(e.verdict.decision is Decision.SANITIZE for e in verdicts if e.verdict),
        approvals_pending=len(database.list_approvals(status="pending")),
        canaries_tripped=sum(event.type == "canary_tripped" for event in events),
        p50_ms=_percentile(latencies, 0.5),
        p95_ms=_percentile(latencies, 0.95),
        findings_by_layer=dict(layers.most_common()),
        top_rules=dict(rules.most_common(TOP_RULES)),
        series=_buckets(events, start, end),
    )
