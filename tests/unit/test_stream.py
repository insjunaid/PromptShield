"""Regression tests for WebSocket task handling.

The first version mixed asyncio tasks with Starlette's anyio cancellation. Tasks leaked when the
handler was cancelled, and the cancellation could escape, which showed up as a flaky test.
"""

import asyncio
from typing import Any, cast

import pytest
from fastapi import WebSocket, WebSocketDisconnect

from promptshield.api.routes.stream import serve_client
from promptshield.events import Subscription
from promptshield.models import Event


class FakeWebSocket:
    def __init__(self, send_error: Exception | None = None) -> None:
        self.send_error = send_error
        self.sent: list[Any] = []
        self.incoming: asyncio.Queue[str | None] = asyncio.Queue()

    async def send_json(self, data: Any) -> None:
        if self.send_error:
            raise self.send_error
        self.sent.append(data)

    async def receive_text(self) -> str:
        message = await self.incoming.get()
        if message is None:
            raise WebSocketDisconnect(1000)
        return message


def serve(socket: FakeWebSocket, subscription: Subscription) -> asyncio.Task[None]:
    return asyncio.create_task(serve_client(cast(WebSocket, socket), subscription))


def running_tasks() -> set[asyncio.Task[Any]]:
    return asyncio.all_tasks() - {asyncio.current_task()}  # type: ignore[operator]


async def test_client_disconnect_ends_both_directions() -> None:
    socket = FakeWebSocket()
    task = serve(socket, Subscription(None, 10))
    await socket.incoming.put(None)
    await asyncio.wait_for(task, timeout=1)
    assert not running_tasks()


@pytest.mark.parametrize("error", [WebSocketDisconnect(1006), RuntimeError("closed")])
async def test_dead_socket_while_sending_ends_cleanly(error: Exception) -> None:
    subscription = Subscription(None, 10)
    subscription.offer(Event(type="tool_call"))
    task = serve(FakeWebSocket(send_error=error), subscription)
    await asyncio.wait_for(task, timeout=1)
    assert not running_tasks()


async def test_cancelling_the_handler_leaves_no_tasks_behind() -> None:
    task = serve(FakeWebSocket(), Subscription(None, 10))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not running_tasks()


async def test_events_are_delivered_as_json() -> None:
    socket = FakeWebSocket()
    subscription = Subscription(None, 10)
    task = serve(socket, subscription)
    subscription.offer(Event(type="tool_call", session_id="s1"))
    await asyncio.sleep(0.01)
    await socket.incoming.put(None)
    await asyncio.wait_for(task, timeout=1)
    assert socket.sent[0]["type"] == "event"
    assert socket.sent[0]["data"]["session_id"] == "s1"
