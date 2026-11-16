"""Stored events, newest first. The dashboard uses `after` to catch up after a reconnect."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from promptshield.api.state import AppState, get_state
from promptshield.models import Event, EventType, Severity

router = APIRouter()

MAX_PAGE = 500


@router.get("/v1/events")
async def list_events(
    state: Annotated[AppState, Depends(get_state)],
    session_id: str | None = None,
    type: EventType | None = None,  # noqa: A002 - the documented query name
    severity: Severity | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
    before: str | None = None,
    after: str | None = None,
) -> list[Event]:
    """Events are redacted when stored, so what comes back is already safe to show. An unknown
    `before` or `after` id is an error, so a client never silently skips events."""
    try:
        return await asyncio.to_thread(
            state.database.list_events,
            session_id=session_id,
            event_type=type,
            severity=severity,
            limit=limit,
            before=before,
            after=after,
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail="unknown event id") from error
