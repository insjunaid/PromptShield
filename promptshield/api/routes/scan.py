"""Direct scanning, also used by SDK mode and tests."""

import asyncio
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends
from pydantic import Field

from promptshield.api.state import AppState, get_state
from promptshield.layers.base import ScanContext
from promptshield.models import ContentItem, Direction, Event, Schema, SessionInfo, Verdict

logger = structlog.get_logger(__name__)

router = APIRouter()


class ScanRequest(Schema):
    items: list[ContentItem] = Field(min_length=1)
    session_id: str | None = None
    user_task: str | None = None


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
    # A direct scan doesn't say which tool produced the content, so it can't be marked sensitive.
    # The gateway knows the tool and records sensitivity (P5.1).
    state.sessions.get(session.id).record_result(
        ",".join(item.source for item in request.items),
        [item.data for item in request.items if item.kind != "image"],
        verdict.findings,
        sensitive=False,
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
