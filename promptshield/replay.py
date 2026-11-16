"""Session list and Attack Replay, built from stored events.

Everything here reads storage, which redacts every write, so nothing needs scrubbing again.
"""

from collections import Counter

from promptshield.models import (
    Event,
    SessionInfo,
    SessionReplay,
    SessionSummary,
)
from promptshield.storage.db import MAX_EVENT_LIMIT, Database


def summarize(database: Database, session: SessionInfo, events: list[Event]) -> SessionSummary:
    """Counts come from the session's verdicts: the worst finding and how each check ended."""
    verdicts = [event.verdict for event in events if event.verdict is not None]
    findings = [finding for verdict in verdicts for finding in verdict.findings]
    worst = max((finding.severity for finding in findings), key=lambda s: s.rank, default=None)
    decisions = Counter(str(verdict.decision) for verdict in verdicts)
    return SessionSummary(
        id=session.id,
        started=session.started,
        user_task=session.user_task,
        run_id=session.run_id,
        shield=session.shield,
        events=len(events),
        findings=len(findings),
        max_severity=worst,
        decisions=dict(decisions),
        lab_run=database.get_lab_run(session.run_id) if session.run_id else None,
    )


def _events(database: Database, session_id: str) -> list[Event]:
    """Newest first, as storage returns them, capped at one page."""
    return database.list_events(session_id=session_id, limit=MAX_EVENT_LIMIT)


def list_summaries(database: Database, limit: int) -> list[SessionSummary]:
    """Newest sessions first. One events query per session: fine for a local dashboard."""
    return [
        summarize(database, session, _events(database, session.id))
        for session in database.list_sessions(limit=limit)
    ]


def get_summary(database: Database, session_id: str) -> SessionSummary | None:
    session = database.get_session(session_id)
    if session is None:
        return None
    return summarize(database, session, _events(database, session_id))


def get_replay(database: Database, session_id: str) -> SessionReplay | None:
    """The timeline oldest first. A session longer than one page keeps its newest events."""
    session = database.get_session(session_id)
    if session is None:
        return None
    newest_first = _events(database, session_id)
    return SessionReplay(
        session=summarize(database, session, newest_first),
        events=list(reversed(newest_first)),
        truncated=len(newest_first) >= MAX_EVENT_LIMIT,
    )
