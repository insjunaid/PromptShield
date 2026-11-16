"""Human-in-the-loop approvals. A call that needs one waits here until someone decides.

No answer in time means no: the policy's `on_timeout` is BLOCK. The waiting call keeps its real
arguments in memory; only a redacted copy is stored or shown.
"""

import asyncio
from datetime import timedelta

import structlog

from promptshield.events import EventBus
from promptshield.models import (
    Approval,
    AutoApprove,
    Direction,
    Event,
    ToolCall,
    Verdict,
    utc_now,
)
from promptshield.policy.engine import PolicyEngine
from promptshield.storage.db import Database

logger = structlog.get_logger(__name__)


class ApprovalError(Exception):
    """Raised for an approval that doesn't exist or is already settled."""


class ApprovalQueue:
    def __init__(self, database: Database, bus: EventBus, engine: PolicyEngine) -> None:
        self._database = database
        self._bus = bus
        self._engine = engine
        self._waiting: dict[str, asyncio.Future[bool]] = {}

    def expire_orphans(self) -> int:
        """Approvals left pending by an earlier process can never be answered: its callers are
        gone. Marking them timed out keeps the dashboard honest."""
        orphans = self._database.list_approvals(status="pending")
        for approval in orphans:
            self._database.save_approval(approval.model_copy(update={"status": "timed_out"}))
        return len(orphans)

    async def request(
        self, tool_call: ToolCall, verdict: Verdict, auto_approve: AutoApprove | None = None
    ) -> bool:
        """True if approved. Auto-approve exists for lab runs and benchmarks."""
        timeout = self._engine.policy.approvals.timeout_seconds
        now = utc_now()
        approval = Approval(
            session_id=tool_call.session_id,
            tool_call=tool_call,
            reasons=verdict.reasons,
            created=now,
            expires=now + timedelta(seconds=timeout),
        )
        # Registered before the approval is stored or announced. Otherwise a quick answer could
        # arrive in between, find no waiter, and be refused as "no longer pending".
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self._waiting[approval.id] = future
        try:
            await asyncio.to_thread(self._database.save_approval, approval)
            await self._publish(approval, "approval_requested")
            if auto_approve is not None:
                return await self._settle(approval, auto_approve == "approve")
            return await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
        except TimeoutError:
            await self._finish(approval, "timed_out")
            return False
        finally:
            self._waiting.pop(approval.id, None)

    async def resolve(self, approval_id: str, approve: bool) -> Approval:
        """Settle a waiting approval. The stored copy is what's returned, so it's redacted."""
        future = self._waiting.get(approval_id)
        stored = await asyncio.to_thread(self._database.get_approval, approval_id)
        if stored is None:
            raise ApprovalError("unknown approval")
        if future is None or future.done() or stored.status != "pending":
            raise ApprovalError("approval is no longer pending")
        await self._settle(stored, approve)
        future.set_result(approve)
        updated = await asyncio.to_thread(self._database.get_approval, approval_id)
        return updated or stored

    async def _settle(self, approval: Approval, approve: bool) -> bool:
        await self._finish(approval, "approved" if approve else "denied")
        return approve

    async def _finish(self, approval: Approval, status: str) -> None:
        done = approval.model_copy(update={"status": status})
        await asyncio.to_thread(self._database.save_approval, done)
        await self._publish(done, "approval_resolved")

    async def _publish(self, approval: Approval, kind: str) -> None:
        call = approval.tool_call
        await self._bus.publish(
            Event(
                session_id=approval.session_id,
                type=kind,  # type: ignore[arg-type]
                direction=Direction.OUTBOUND,
                tool=f"{call.server}.{call.tool}",
                payload={
                    "approval_id": approval.id,
                    "status": approval.status,
                    "reasons": approval.reasons,
                    "args": call.args,
                    "expires": approval.expires.isoformat(),
                },
            )
        )
