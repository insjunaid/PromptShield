"""Sessions for the dashboard: a list, one summary, and the Attack Replay timeline. Read-only."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from promptshield import replay
from promptshield.api.state import AppState, get_state
from promptshield.models import SessionReplay, SessionSummary

router = APIRouter()

State = Annotated[AppState, Depends(get_state)]


@router.get("/v1/sessions")
async def list_sessions(
    state: State, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[SessionSummary]:
    return await asyncio.to_thread(replay.list_summaries, state.database, limit)


@router.get("/v1/sessions/{session_id}")
async def get_session(session_id: str, state: State) -> SessionSummary:
    summary = await asyncio.to_thread(replay.get_summary, state.database, session_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="unknown session")
    return summary


@router.get("/v1/sessions/{session_id}/replay")
async def get_replay(session_id: str, state: State) -> SessionReplay:
    timeline = await asyncio.to_thread(replay.get_replay, state.database, session_id)
    if timeline is None:
        raise HTTPException(status_code=404, detail="unknown session")
    return timeline
