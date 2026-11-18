"""Direct scanning, also used by SDK mode and tests."""

import asyncio
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends
from pydantic import Field

from promptshield.api.state import AppState, get_state
from promptshield.layers.base import ScanContext
from promptshield.models import (
    ContentItem,
    Direction,
    Event,
    Schema,
    SessionInfo,
    ToolCall,
    Verdict,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


class ScanRequest(Schema):
    items: list[ContentItem] = Field(min_length=1)
    session_id: str | None = None
    user_task: str | None = None
    # "server.tool" that produced the content, when known (the Claude Code hooks send it), so the
    # policy can mark private results, such as a file read, for taint tracking.
    tool: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _sensitive(state: AppState, request: ScanRequest, session_id: str) -> bool:
    if request.tool is None:
        return False
    server, tool = request.tool.split(".", 1)
    call = ToolCall(session_id=session_id, server=server, tool=tool, args={})
    return state.engine.has_sensitive_output(call)


async def _load_session(state: AppState, request: ScanRequest) -> SessionInfo:
    """Storage trouble must not stop a scan, so a failure falls back to a fresh session."""
    new_session = SessionInfo(user_task=request.user_task)
    if request.session_id is not None:
        new_session.id = request.session_id
    try:
        known = None
        if request.session_id is not None:
            known = await asyncio.to_thread(state.database.get_session, request.session_id)
        if known is not None:
            return known
        await asyncio.to_thread(state.database.save_session, new_session)
    except Exception as error:
        logger.error("session_storage_failed", error=type(error).__name__)
    return new_session


def _without_content(verdict: Verdict) -> Verdict:
    """Used when redaction failed: keep the decision, drop everything that holds scanned text."""
    return verdict.model_copy(update={"findings": [], "segments": [], "sanitized_items": None})


@router.post("/v1/scan")
async def scan(request: ScanRequest, state: Annotated[AppState, Depends(get_state)]) -> Verdict:
    session = await _load_session(state, request)
    context = ScanContext(session=session, items=request.items)
    verdict = await state.shield.inspect(context)
    # Sensitive only when the caller names the tool; the gateway records its own calls (P5.1).
    state.sessions.get(session.id).record_result(
        ",".join(item.source for item in request.items),
        [item.data for item in request.items if item.kind != "image"],
        verdict.findings,
        sensitive=_sensitive(state, request, session.id),
    )
    published = await state.bus.publish(
        Event(
            session_id=session.id,
            type="verdict",
            direction=Direction.INBOUND,
            verdict=verdict,
            payload={"sources": [item.source for item in request.items]},
        )
    )
    return published.verdict or _without_content(verdict)
