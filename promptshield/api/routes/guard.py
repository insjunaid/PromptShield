"""Checks a tool call before it runs (L4 only). Used by SDK mode now and the gateway in P5."""

import asyncio
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends

from promptshield.api.state import AppState, get_state
from promptshield.models import Direction, Event, ToolCall, Verdict

logger = structlog.get_logger(__name__)

router = APIRouter()


async def _user_task(state: AppState, session_id: str) -> str | None:
    """The task lives on the stored session. Storage trouble only skips the alignment check."""
    try:
        session = await asyncio.to_thread(state.database.get_session, session_id)
    except Exception as error:
        logger.error("session_lookup_failed", error=type(error).__name__)
        return None
    return session.user_task if session else None


@router.post("/v1/guard/tool-call")
async def guard_tool_call(
    tool_call: ToolCall, state: Annotated[AppState, Depends(get_state)]
) -> Verdict:
    verdict = await state.guard.evaluate(tool_call, await _user_task(state, tool_call.session_id))
    published = await state.bus.publish(
        Event(
            session_id=tool_call.session_id,
            type="tool_call",
            direction=Direction.OUTBOUND,
            tool=f"{tool_call.server}.{tool_call.tool}",
            verdict=verdict,
            payload={"args": tool_call.args},
        )
    )
    return published.verdict or verdict.model_copy(update={"findings": []})
