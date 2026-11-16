"""SQLite storage.

Each row holds the validated model as JSON, plus the columns needed for filtering. Reading a row
back validates it again, and timestamps keep their timezone, which SQLite's own types would lose.

These methods block, so async code must call them through `asyncio.to_thread`.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from sqlite3 import Connection
from typing import Any

from sqlalchemy import Engine, event
from sqlmodel import Field, Session, SQLModel, col, create_engine, select

from promptshield.models import (
    Approval,
    ApprovalStatus,
    Event,
    EventType,
    LabRunOutcome,
    SessionInfo,
    Severity,
    ToolPin,
)
from promptshield.redact import Redactor

DEFAULT_EVENT_LIMIT = 100
MAX_EVENT_LIMIT = 500
BUSY_TIMEOUT_SECONDS = 5


class EventRow(SQLModel, table=True):
    __tablename__ = "events"  # type: ignore[assignment]

    # Pagination uses seq, because ULIDs made in the same millisecond aren't ordered.
    seq: int | None = Field(default=None, primary_key=True)
    id: str = Field(unique=True, index=True)
    session_id: str | None = Field(default=None, index=True)
    type: str = Field(index=True)
    severity_rank: int | None = Field(default=None, index=True)
    data: str


class SessionRow(SQLModel, table=True):
    __tablename__ = "sessions"  # type: ignore[assignment]

    id: str = Field(primary_key=True)
    started: str = Field(index=True)
    run_id: str | None = Field(default=None, index=True)
    data: str


class ApprovalRow(SQLModel, table=True):
    __tablename__ = "approvals"  # type: ignore[assignment]

    id: str = Field(primary_key=True)
    session_id: str = Field(index=True)
    status: str = Field(index=True)
    data: str


class LabRunRow(SQLModel, table=True):
    __tablename__ = "lab_runs"  # type: ignore[assignment]

    run_id: str = Field(primary_key=True)
    scenario_id: str = Field(index=True)
    session_id: str | None = Field(default=None, index=True)
    shield: bool
    status: str = Field(index=True)
    data: str


class BenchRunRow(SQLModel, table=True):
    __tablename__ = "bench_runs"  # type: ignore[assignment]

    id: str = Field(primary_key=True)
    suite: str = Field(index=True)
    started: str = Field(index=True)
    data: str


class RegistryPinRow(SQLModel, table=True):
    __tablename__ = "registry_pins"  # type: ignore[assignment]

    server: str = Field(primary_key=True)
    tool: str = Field(primary_key=True)
    data: str


def _configure_connection(connection: Connection, _record: Any) -> None:
    """WAL lets the dashboard read while the gateway writes."""
    cursor = connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def _severity_rank(item: Event) -> int | None:
    if item.verdict is None or not item.verdict.findings:
        return None
    return max(finding.severity.rank for finding in item.verdict.findings)


class Database:
    """All writes pass through the redactor, so no caller can store a secret by accident."""

    def __init__(self, path: Path, redactor: Redactor) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._redactor = redactor
        self._engine: Engine = create_engine(
            f"sqlite:///{path.as_posix()}",
            connect_args={"check_same_thread": False, "timeout": BUSY_TIMEOUT_SECONDS},
        )
        event.listen(self._engine, "connect", _configure_connection)
        SQLModel.metadata.create_all(self._engine)

    def close(self) -> None:
        self._engine.dispose()

    @contextmanager
    def session(self) -> Iterator[Session]:
        with Session(self._engine) as session:
            yield session

    # Events

    def add_event(self, item: Event) -> None:
        safe = self._redactor.scrub_model(item)
        row = EventRow(
            id=safe.id,
            session_id=safe.session_id,
            type=safe.type,
            severity_rank=_severity_rank(safe),
            data=safe.model_dump_json(),
        )
        with self.session() as session:
            session.add(row)
            session.commit()

    def list_events(
        self,
        *,
        session_id: str | None = None,
        event_type: EventType | None = None,
        severity: Severity | None = None,
        limit: int = DEFAULT_EVENT_LIMIT,
        before: str | None = None,
        after: str | None = None,
    ) -> list[Event]:
        """Return events newest first. `severity` means that level or worse.

        With `after`, the page holds the events right after that id, so a reconnecting client
        catches up from where it stopped instead of losing the oldest ones it missed.

        Raises LookupError if `before` or `after` is an unknown id.
        """
        query = select(EventRow)
        if session_id is not None:
            query = query.where(EventRow.session_id == session_id)
        if event_type is not None:
            query = query.where(EventRow.type == event_type)
        if severity is not None:
            query = query.where(col(EventRow.severity_rank) >= severity.rank)

        with self.session() as session:
            if before is not None:
                query = query.where(col(EventRow.seq) < self._seq_of(session, before))
            if after is not None:
                query = query.where(col(EventRow.seq) > self._seq_of(session, after))
            order = col(EventRow.seq).asc() if after is not None else col(EventRow.seq).desc()
            page_size = max(1, min(limit, MAX_EVENT_LIMIT))
            rows = session.exec(query.order_by(order).limit(page_size)).all()

        items = [Event.model_validate_json(row.data) for row in rows]
        return list(reversed(items)) if after is not None else items

    @staticmethod
    def _seq_of(session: Session, event_id: str) -> int:
        seq = session.exec(select(EventRow.seq).where(EventRow.id == event_id)).first()
        if seq is None:
            raise LookupError(f"unknown event id: {event_id}")
        return seq

    # Sessions

    def save_session(self, item: SessionInfo) -> None:
        safe = self._redactor.scrub_model(item)
        row = SessionRow(
            id=safe.id,
            started=safe.started.isoformat(),
            run_id=safe.run_id,
            data=safe.model_dump_json(),
        )
        with self.session() as session:
            session.merge(row)
            session.commit()

    def get_session(self, session_id: str) -> SessionInfo | None:
        with self.session() as session:
            row = session.get(SessionRow, session_id)
        return SessionInfo.model_validate_json(row.data) if row else None

    def list_sessions(self, limit: int = DEFAULT_EVENT_LIMIT) -> list[SessionInfo]:
        query = select(SessionRow).order_by(col(SessionRow.started).desc()).limit(limit)
        with self.session() as session:
            rows = session.exec(query).all()
        return [SessionInfo.model_validate_json(row.data) for row in rows]

    # Approvals

    def save_approval(self, item: Approval) -> None:
        """Store a redacted copy. The live call keeps its real arguments in memory only."""
        safe = self._redactor.scrub_model(item)
        row = ApprovalRow(
            id=safe.id,
            session_id=safe.session_id,
            status=safe.status,
            data=safe.model_dump_json(),
        )
        with self.session() as session:
            session.merge(row)
            session.commit()

    def get_approval(self, approval_id: str) -> Approval | None:
        with self.session() as session:
            row = session.get(ApprovalRow, approval_id)
        return Approval.model_validate_json(row.data) if row else None

    def list_approvals(self, status: ApprovalStatus | None = None) -> list[Approval]:
        query = select(ApprovalRow).order_by(col(ApprovalRow.id).desc())
        if status is not None:
            query = query.where(ApprovalRow.status == status)
        with self.session() as session:
            rows = session.exec(query).all()
        return [Approval.model_validate_json(row.data) for row in rows]

    # Lab runs

    def save_lab_run(self, item: LabRunOutcome) -> None:
        safe = self._redactor.scrub_model(item)
        row = LabRunRow(
            run_id=safe.run_id,
            scenario_id=safe.scenario_id,
            session_id=safe.session_id,
            shield=safe.shield,
            status=safe.status,
            data=safe.model_dump_json(),
        )
        with self.session() as session:
            session.merge(row)
            session.commit()

    def get_lab_run(self, run_id: str) -> LabRunOutcome | None:
        with self.session() as session:
            row = session.get(LabRunRow, run_id)
        return LabRunOutcome.model_validate_json(row.data) if row else None

    # Tool pins

    def save_pin(self, item: ToolPin) -> None:
        row = RegistryPinRow(server=item.server, tool=item.tool, data=item.model_dump_json())
        with self.session() as session:
            session.merge(row)
            session.commit()

    def get_pin(self, server: str, tool: str) -> ToolPin | None:
        with self.session() as session:
            row = session.get(RegistryPinRow, (server, tool))
        return ToolPin.model_validate_json(row.data) if row else None

    def list_pins(self) -> list[ToolPin]:
        with self.session() as session:
            rows = session.exec(select(RegistryPinRow)).all()
        return [ToolPin.model_validate_json(row.data) for row in rows]
