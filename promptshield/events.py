"""In-process event bus: save each event, then send it to every live subscriber.

The bus runs on the agent's path, so it never raises into the caller and never waits for a slow
client. A client that falls behind loses its oldest events and recovers them from the API.
"""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager

import structlog

from promptshield.models import Event
from promptshield.redact import Redactor
from promptshield.storage.db import Database

logger = structlog.get_logger(__name__)


class Subscription:
    """One client's queue. `session_id` limits it to a single session."""

    def __init__(self, session_id: str | None, queue_size: int) -> None:
        self.session_id = session_id
        self.dropped = 0
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)

    async def get(self) -> Event:
        return await self._queue.get()

    def wants(self, event: Event) -> bool:
        return self.session_id is None or event.session_id == self.session_id

    def offer(self, event: Event) -> None:
        """Add an event without waiting, dropping the oldest one if the queue is full."""
        if self._queue.full():
            self._queue.get_nowait()
            self.dropped += 1
        self._queue.put_nowait(event)


class EventBus:
    def __init__(
        self, database: Database | None, redactor: Redactor, queue_size: int = 1000
    ) -> None:
        self._database = database
        self._redactor = redactor
        self._queue_size = queue_size
        self._subscribers: set[Subscription] = set()
        # One publish at a time, so storage order and delivery order always match.
        self._lock = asyncio.Lock()

    @property
    def redactor(self) -> Redactor:
        """Shared with storage, so a secret registered here is masked everywhere it is kept."""
        return self._redactor

    @contextmanager
    def subscribe(self, session_id: str | None = None) -> Iterator[Subscription]:
        subscription = Subscription(session_id, self._queue_size)
        self._subscribers.add(subscription)
        try:
            yield subscription
        finally:
            self._subscribers.discard(subscription)

    async def publish(self, event: Event) -> Event:
        """Redact, save and deliver an event. Returns what subscribers actually received."""
        safe = self._redact(event)
        async with self._lock:
            await self._save(safe)
            for subscription in self._subscribers:
                if subscription.wants(safe):
                    subscription.offer(safe)
        return safe

    def _redact(self, event: Event) -> Event:
        """Fail closed: if redaction breaks, send a placeholder and never the raw event."""
        try:
            return self._redactor.scrub_model(event)
        except Exception as error:
            logger.error("event_redaction_failed", error=type(error).__name__)
            return Event(
                id=event.id,
                ts=event.ts,
                session_id=event.session_id,
                type=event.type,
                payload={"redaction_failed": True},
            )

    async def _save(self, event: Event) -> None:
        if self._database is None:
            return
        try:
            await asyncio.to_thread(self._database.add_event, event)
        except Exception as error:
            logger.error("event_save_failed", error=type(error).__name__)
