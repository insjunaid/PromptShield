"""The approval queue: approve, deny, time out, auto-answer, and survive a restart."""

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest

from promptshield.approvals import ApprovalError, ApprovalQueue
from promptshield.config import Settings
from promptshield.events import EventBus
from promptshield.models import Decision, ToolCall, Verdict
from promptshield.policy.engine import PolicyEngine
from promptshield.policy.schema import load_policy
from promptshield.redact import Redactor
from promptshield.storage.db import Database

CONFIG = Settings(_env_file=None)  # type: ignore[call-arg]
CANARY = "sk-canary-a1b2c3d4e5f6"
CALL = ToolCall(
    session_id="s1",
    server="http",
    tool="http_post",
    args={"url": "http://example.org", "body": CANARY},
)
VERDICT = Verdict(
    decision=Decision.REQUIRE_APPROVAL, risk_score=0.5, reasons=["unknown destination"]
)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(tmp_path / "test.db", Redactor())
    yield db
    db.close()


def queue(database: Database, timeout: float = 5.0) -> ApprovalQueue:
    policy = load_policy(CONFIG.policy_path)
    approvals = policy.approvals.model_copy(update={"timeout_seconds": timeout})
    engine = PolicyEngine(policy.model_copy(update={"approvals": approvals}))
    return ApprovalQueue(database, EventBus(database, Redactor()), engine)


async def pending_id(database: Database) -> str:
    """Waits until the request is stored, then returns its id."""
    for _ in range(200):
        pending = database.list_approvals(status="pending")
        if pending:
            return pending[0].id
        await asyncio.sleep(0.01)
    raise AssertionError("no pending approval appeared")


async def test_an_approved_call_returns_true(database: Database) -> None:
    approvals = queue(database)
    waiting = asyncio.create_task(approvals.request(CALL, VERDICT))
    approval = await approvals.resolve(await pending_id(database), approve=True)
    assert await waiting is True
    assert approval.status == "approved"


async def test_a_denied_call_returns_false(database: Database) -> None:
    approvals = queue(database)
    waiting = asyncio.create_task(approvals.request(CALL, VERDICT))
    await approvals.resolve(await pending_id(database), approve=False)
    assert await waiting is False
    assert database.list_approvals()[0].status == "denied"


async def test_no_answer_in_time_means_no(database: Database) -> None:
    """The policy's on_timeout is BLOCK."""
    assert await queue(database, timeout=0.2).request(CALL, VERDICT) is False
    assert database.list_approvals()[0].status == "timed_out"


async def test_an_unknown_approval_cannot_be_resolved(database: Database) -> None:
    with pytest.raises(ApprovalError, match="unknown"):
        await queue(database).resolve("no-such-id", approve=True)


async def test_an_approval_cannot_be_settled_twice(database: Database) -> None:
    approvals = queue(database)
    waiting = asyncio.create_task(approvals.request(CALL, VERDICT))
    approval_id = await pending_id(database)
    await approvals.resolve(approval_id, approve=False)
    await waiting
    with pytest.raises(ApprovalError, match="no longer pending"):
        await approvals.resolve(approval_id, approve=True)


async def test_a_timed_out_approval_cannot_be_approved_late(database: Database) -> None:
    approvals = queue(database, timeout=0.2)
    await approvals.request(CALL, VERDICT)
    with pytest.raises(ApprovalError):
        await approvals.resolve(database.list_approvals()[0].id, approve=True)


@pytest.mark.parametrize(("auto", "expected"), [("approve", True), ("deny", False)])
async def test_auto_answers_for_lab_runs(database: Database, auto: str, expected: bool) -> None:
    assert await queue(database).request(CALL, VERDICT, auto_approve=auto) is expected  # type: ignore[arg-type]
    assert database.list_approvals()[0].status == ("approved" if expected else "denied")


async def test_requests_and_answers_are_published_as_events(database: Database) -> None:
    await queue(database).request(CALL, VERDICT, auto_approve="deny")
    types = [event.type for event in database.list_events(session_id="s1")]
    assert sorted(types) == ["approval_requested", "approval_resolved"]


async def test_stored_approvals_and_events_are_redacted(database: Database) -> None:
    await queue(database).request(CALL, VERDICT, auto_approve="deny")
    stored = database.list_approvals()[0].model_dump_json()
    events = " ".join(str(event.payload) for event in database.list_events(session_id="s1"))
    assert "a1b2c3d4" not in stored
    assert "a1b2c3d4" not in events


async def test_the_waiting_call_keeps_its_real_arguments(database: Database) -> None:
    """Only the stored copy is redacted: the call that runs after approval must be intact."""
    approvals = queue(database)
    waiting = asyncio.create_task(approvals.request(CALL, VERDICT))
    await approvals.resolve(await pending_id(database), approve=True)
    await waiting
    assert CALL.args["body"] == CANARY


async def test_orphans_from_a_previous_process_are_expired(database: Database) -> None:
    first = queue(database)
    task = asyncio.create_task(first.request(CALL, VERDICT))
    await pending_id(database)
    task.cancel()
    assert queue(database).expire_orphans() == 1
    assert database.list_approvals()[0].status == "timed_out"


async def test_the_expiry_matches_the_policy_timeout(database: Database) -> None:
    await queue(database, timeout=30).request(CALL, VERDICT, auto_approve="deny")
    approval = database.list_approvals()[0]
    assert (approval.expires - approval.created).total_seconds() == pytest.approx(30)
