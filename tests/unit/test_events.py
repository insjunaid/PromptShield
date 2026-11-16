"""The bus is on the agent's path, so it must never block or raise."""

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from structlog.testing import capture_logs

from promptshield.events import EventBus
from promptshield.models import Event
from promptshield.redact import Redactor
from promptshield.storage.db import Database

CANARY = "sk-canary-a1b2c3d4e5f6"


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "test.db", Redactor())
    yield db
    db.close()


@pytest.fixture
def bus(database: Database) -> EventBus:
    return EventBus(database, Redactor(), queue_size=3)


def make_event(n: int = 0, session_id: str | None = "s1") -> Event:
    return Event(type="tool_call", session_id=session_id, payload={"n": n})


async def next_event(subscription: object) -> Event:
    return await asyncio.wait_for(subscription.get(), timeout=1)  # type: ignore[attr-defined]


async def test_every_subscriber_receives_the_event(bus: EventBus) -> None:
    event = make_event()
    with bus.subscribe() as first, bus.subscribe() as second:
        await bus.publish(event)
        assert await next_event(first) == event
        assert await next_event(second) == event


async def test_events_are_saved(bus: EventBus, database: Database) -> None:
    event = make_event()
    await bus.publish(event)
    assert database.list_events() == [event]


async def test_subscribers_never_see_raw_secrets(bus: EventBus, database: Database) -> None:
    with bus.subscribe() as subscription:
        await bus.publish(Event(type="tool_call", payload={"args": {"data": CANARY}}))
        delivered = await next_event(subscription)
    assert "a1b2c3d4" not in delivered.model_dump_json()
    assert "a1b2c3d4" not in database.list_events()[0].model_dump_json()


async def test_session_filter_only_delivers_that_session(bus: EventBus) -> None:
    wanted = make_event(session_id="a")
    with bus.subscribe("a") as subscription:
        await bus.publish(make_event(session_id="b"))
        await bus.publish(make_event(session_id=None))
        await bus.publish(wanted)
        assert await next_event(subscription) == wanted


async def test_slow_client_loses_its_oldest_events_and_never_blocks(bus: EventBus) -> None:
    events = [make_event(n) for n in range(5)]
    with bus.subscribe() as subscription:
        for event in events:
            await asyncio.wait_for(bus.publish(event), timeout=1)
        assert subscription.dropped == 2
        assert [await next_event(subscription) for _ in range(3)] == events[2:]


async def test_a_dropped_event_can_be_recovered_from_storage(
    bus: EventBus, database: Database
) -> None:
    events = [make_event(n) for n in range(5)]
    with bus.subscribe():
        for event in events:
            await bus.publish(event)
    assert database.list_events(after=events[0].id)[-1] == events[1]


async def test_unsubscribed_clients_stop_receiving(bus: EventBus) -> None:
    with bus.subscribe() as subscription:
        pass
    await bus.publish(make_event())
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(subscription.get(), timeout=0.01)


async def test_a_client_error_still_unsubscribes(bus: EventBus) -> None:
    with pytest.raises(RuntimeError), bus.subscribe():
        raise RuntimeError("socket closed")
    assert not bus._subscribers


async def test_a_storage_failure_does_not_stop_live_events(database: Database) -> None:
    class BrokenDatabase(Database):
        def add_event(self, item: Event) -> None:
            raise OSError(f"disk full writing {CANARY}")

    broken = BrokenDatabase.__new__(BrokenDatabase)
    bus = EventBus(broken, Redactor())
    event = make_event()
    with capture_logs() as logs, bus.subscribe() as subscription:
        await bus.publish(event)
        assert await next_event(subscription) == event
    assert any(entry["event"] == "event_save_failed" for entry in logs)
    assert "a1b2c3d4" not in str(logs)


async def test_redaction_failure_sends_a_placeholder_not_the_event(database: Database) -> None:
    class BrokenRedactor(Redactor):
        def scrub_model(self, model):  # type: ignore[no-untyped-def]
            if model.payload.get("args"):
                raise ValueError("cannot scrub")
            return model

    bus = EventBus(database, BrokenRedactor())
    event = Event(type="tool_call", session_id="s1", payload={"args": {"data": CANARY}})
    with bus.subscribe() as subscription:
        await bus.publish(event)
        delivered = await next_event(subscription)
    assert delivered.id == event.id
    assert delivered.payload == {"redaction_failed": True}


async def test_bus_works_without_storage() -> None:
    bus = EventBus(None, Redactor())
    event = make_event()
    with bus.subscribe() as subscription:
        await bus.publish(event)
        assert await next_event(subscription) == event


async def test_concurrent_publishes_keep_storage_and_delivery_in_the_same_order(
    database: Database,
) -> None:
    bus = EventBus(database, Redactor(), queue_size=100)
    events = [make_event(n) for n in range(30)]
    with bus.subscribe() as subscription:
        await asyncio.gather(*(bus.publish(event) for event in events))
        delivered = [await next_event(subscription) for _ in events]
    stored = list(reversed(database.list_events()))
    assert [item.id for item in delivered] == [item.id for item in stored]
    assert {item.id for item in stored} == {item.id for item in events}


async def test_publishing_does_not_block_the_event_loop(database: Database) -> None:
    class SlowDatabase(Database):
        def add_event(self, item: Event) -> None:
            import time

            time.sleep(0.05)

    slow = SlowDatabase.__new__(SlowDatabase)
    bus = EventBus(slow, Redactor())
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.005)

    task = asyncio.create_task(ticker())
    await bus.publish(make_event())
    task.cancel()
    assert ticks >= 3
