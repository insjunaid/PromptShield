"""Storage must redact on write, keep order, and return valid models."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from promptshield.models import (
    Approval,
    Decision,
    Event,
    Finding,
    SessionInfo,
    Severity,
    ToolCall,
    ToolPin,
    Verdict,
)
from promptshield.redact import Redactor
from promptshield.storage.db import BenchRunRow, Database, LabRunRow

CANARY = "sk-canary-a1b2c3d4e5f6"


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "nested" / "test.db", Redactor())
    yield db
    db.close()


def verdict_event(severity: Severity, session_id: str = "s1") -> Event:
    finding = Finding(
        layer="L2",
        rule_id="L2.test",
        title="test",
        severity=severity,
        score=0.5,
        evidence="x",
        latency_ms=1,
    )
    verdict = Verdict(decision=Decision.BLOCK, risk_score=0.5, findings=[finding])
    return Event(type="verdict", session_id=session_id, verdict=verdict)


def add_many(database: Database, count: int) -> list[Event]:
    events = [Event(type="tool_call", session_id="s1", payload={"n": n}) for n in range(count)]
    for event in events:
        database.add_event(event)
    return events


def make_approval(status: str = "pending") -> Approval:
    return Approval.model_validate(
        {
            "session_id": "s1",
            "tool_call": ToolCall(
                session_id="s1", tool="http_post", server="http", args={"data": CANARY}
            ),
            "reasons": ["unknown destination"],
            "expires": datetime.now(UTC) + timedelta(minutes=2),
            "status": status,
        }
    )


def test_all_documented_tables_exist(database: Database) -> None:
    with database.session() as session:
        tables = set(inspect(session.get_bind()).get_table_names())
    assert {
        "events",
        "sessions",
        "approvals",
        "lab_runs",
        "bench_runs",
        "registry_pins",
    } <= tables


def test_database_uses_wal_for_concurrent_reads(database: Database) -> None:
    with database.session() as session:
        mode = session.connection().exec_driver_sql("PRAGMA journal_mode").scalar()
    assert mode == "wal"


def test_event_round_trip_keeps_the_timestamp_timezone(database: Database) -> None:
    event = Event(type="session_start", session_id="s1", payload={"task": "summarize"})
    database.add_event(event)
    [stored] = database.list_events()
    assert stored == event
    assert stored.ts.utcoffset() == timedelta(0)


def test_event_secrets_are_redacted_on_write(database: Database) -> None:
    database.add_event(Event(type="tool_call", payload={"args": {"data": CANARY}}))
    with database.session() as session:
        raw = session.connection().exec_driver_sql("SELECT data FROM events").scalar()
    assert "a1b2c3d4" not in str(raw)


def test_duplicate_event_id_is_refused(database: Database) -> None:
    event = Event(type="tool_call")
    database.add_event(event)
    with pytest.raises(IntegrityError):
        database.add_event(event)


def test_events_come_back_newest_first(database: Database) -> None:
    events = add_many(database, 5)
    assert database.list_events() == list(reversed(events))


def test_limit_is_applied_and_capped(database: Database) -> None:
    add_many(database, 3)
    assert len(database.list_events(limit=2)) == 2
    assert len(database.list_events(limit=0)) == 1


def test_before_pages_through_older_events(database: Database) -> None:
    events = add_many(database, 5)
    assert database.list_events(before=events[2].id) == [events[1], events[0]]


def test_after_returns_newer_events_newest_first(database: Database) -> None:
    events = add_many(database, 5)
    assert database.list_events(after=events[2].id) == [events[4], events[3]]


def test_after_with_a_limit_resumes_right_after_the_id(database: Database) -> None:
    events = add_many(database, 6)
    assert database.list_events(after=events[0].id, limit=2) == [events[2], events[1]]


def test_order_follows_insertion_even_if_ids_sort_differently(database: Database) -> None:
    first = Event(id="ZZZZZZZZZZZZZZZZZZZZZZZZZZ", type="tool_call")
    second = Event(id="00000000000000000000000000", type="tool_call")
    database.add_event(first)
    database.add_event(second)
    assert database.list_events(after=first.id) == [second]


def test_unknown_page_id_raises(database: Database) -> None:
    with pytest.raises(LookupError):
        database.list_events(before="missing")
    with pytest.raises(LookupError):
        database.list_events(after="missing")


def test_filters_by_session_and_type(database: Database) -> None:
    database.add_event(Event(type="tool_call", session_id="a"))
    database.add_event(Event(type="tool_result", session_id="a"))
    database.add_event(Event(type="tool_call", session_id="b"))
    assert len(database.list_events(session_id="a")) == 2
    assert len(database.list_events(event_type="tool_call")) == 2
    assert len(database.list_events(session_id="a", event_type="tool_call")) == 1


def test_severity_filter_means_that_level_or_worse(database: Database) -> None:
    database.add_event(verdict_event(Severity.LOW))
    high = verdict_event(Severity.HIGH)
    critical = verdict_event(Severity.CRITICAL)
    database.add_event(high)
    database.add_event(critical)
    database.add_event(Event(type="tool_call"))
    assert database.list_events(severity=Severity.HIGH) == [critical, high]


def test_session_round_trip_and_update(database: Database) -> None:
    session = SessionInfo(user_task="Summarize a page", run_id="r1")
    database.save_session(session)
    assert database.get_session(session.id) == session
    updated = session.model_copy(update={"history_summary": "Fetched one page"})
    database.save_session(updated)
    assert database.get_session(session.id) == updated
    assert len(database.list_sessions()) == 1


def test_missing_session_is_none(database: Database) -> None:
    assert database.get_session("missing") is None


def test_sessions_come_back_newest_first(database: Database) -> None:
    start = datetime(2026, 11, 5, tzinfo=UTC)
    older = SessionInfo(started=start)
    newer = SessionInfo(started=start + timedelta(hours=1))
    database.save_session(older)
    database.save_session(newer)
    assert database.list_sessions() == [newer, older]


def test_session_task_secrets_are_redacted(database: Database) -> None:
    session = SessionInfo(user_task=f"Use key {CANARY}")
    database.save_session(session)
    stored = database.get_session(session.id)
    assert stored is not None
    assert "a1b2c3d4" not in str(stored.user_task)


def test_approval_args_are_redacted_when_stored(database: Database) -> None:
    approval = make_approval()
    database.save_approval(approval)
    stored = database.get_approval(approval.id)
    assert stored is not None
    assert "a1b2c3d4" not in stored.model_dump_json()


def test_saving_does_not_change_the_live_approval(database: Database) -> None:
    approval = make_approval()
    database.save_approval(approval)
    assert approval.tool_call.args["data"] == CANARY


def test_approvals_filter_by_status_and_update(database: Database) -> None:
    pending = make_approval()
    database.save_approval(pending)
    database.save_approval(make_approval("denied"))
    assert [item.id for item in database.list_approvals("pending")] == [pending.id]
    database.save_approval(pending.model_copy(update={"status": "approved"}))
    assert database.list_approvals("pending") == []
    assert len(database.list_approvals()) == 2


def test_missing_approval_is_none(database: Database) -> None:
    assert database.get_approval("missing") is None


def test_pins_are_keyed_by_server_and_tool(database: Database) -> None:
    pin = ToolPin(server="mail", tool="send_email", sha256="abc")
    database.save_pin(pin)
    database.save_pin(ToolPin(server="evil", tool="send_email", sha256="def"))
    assert database.get_pin("mail", "send_email") == pin
    assert database.get_pin("mail", "missing") is None
    assert len(database.list_pins()) == 2


def test_changing_a_pin_replaces_it(database: Database) -> None:
    database.save_pin(ToolPin(server="mail", tool="send_email", sha256="abc"))
    database.save_pin(ToolPin(server="mail", tool="send_email", sha256="def", status="quarantined"))
    pin = database.get_pin("mail", "send_email")
    assert pin is not None
    assert (pin.sha256, pin.status) == ("def", "quarantined")


def test_lab_and_bench_rows_can_be_stored(database: Database) -> None:
    with database.session() as session:
        session.add(
            LabRunRow(
                run_id="r1",
                scenario_id="A02",
                shield=True,
                status="done",
                data=json.dumps({"attack_succeeded": False}),
            )
        )
        session.add(
            BenchRunRow(id="b1", suite="lab", started="2026-11-05", data=json.dumps({"asr": 0.1}))
        )
        session.commit()
        assert session.get(LabRunRow, "r1") is not None
        assert session.get(BenchRunRow, "b1") is not None


def test_data_survives_reopening_the_file(tmp_path: Path) -> None:
    path = tmp_path / "test.db"
    first = Database(path, Redactor())
    first.add_event(Event(type="tool_call"))
    first.close()
    second = Database(path, Redactor())
    assert len(second.list_events()) == 1
    second.close()
