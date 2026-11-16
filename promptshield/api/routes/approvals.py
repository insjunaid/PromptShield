"""Approvals: list them, and decide one. Deciding needs the admin token."""

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field

from promptshield.api.auth import require_admin
from promptshield.api.state import AppState, get_state
from promptshield.approvals import ApprovalError
from promptshield.models import Approval, ApprovalStatus, Schema

router = APIRouter()


class ApprovalDecision(Schema):
    decision: Literal["approve", "deny"]
    note: str | None = Field(default=None, max_length=500)


class ApprovalView(Approval):
    """An approval with what a reviewer needs beside it: the user's task and where the call goes."""

    user_task: str | None = None
    destination: str | None = None


def _view(state: AppState, approval: Approval) -> ApprovalView:
    call = approval.tool_call
    rule = state.engine.policy.tools.get(f"{call.server}.{call.tool}")
    target = call.args.get(rule.arg_destination) if rule and rule.arg_destination else None
    session = state.database.get_session(approval.session_id)
    return ApprovalView(
        **approval.model_dump(),
        user_task=session.user_task if session else None,
        destination=str(target) if target is not None else None,
    )


def _list(state: AppState, status: ApprovalStatus | None) -> list[ApprovalView]:
    return [_view(state, item) for item in state.database.list_approvals(status=status)]


@router.get("/v1/approvals")
async def list_approvals(
    state: Annotated[AppState, Depends(get_state)], status: ApprovalStatus | None = None
) -> list[ApprovalView]:
    return await asyncio.to_thread(_list, state, status)


@router.post("/v1/approvals/{approval_id}", dependencies=[Depends(require_admin)])
async def decide_approval(
    approval_id: str,
    body: ApprovalDecision,
    state: Annotated[AppState, Depends(get_state)],
) -> Approval:
    try:
        return await state.approvals.resolve(approval_id, body.decision == "approve")
    except ApprovalError as error:
        known = await _exists(state, approval_id)
        raise HTTPException(status_code=409 if known else 404, detail=str(error)) from error


async def _exists(state: AppState, approval_id: str) -> bool:
    return state.database.get_approval(approval_id) is not None
