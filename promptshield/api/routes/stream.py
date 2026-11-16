"""Live event stream for the dashboard."""

import json
from collections.abc import Awaitable, Callable

import anyio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from promptshield.api.state import get_state
from promptshield.events import Subscription

router = APIRouter()

Direction = Callable[[WebSocket, Subscription], Awaitable[None]]


def allowed_origins(dashboard_port: int) -> list[str]:
    return [f"http://localhost:{dashboard_port}", f"http://127.0.0.1:{dashboard_port}"]


async def _send_events(websocket: WebSocket, subscription: Subscription) -> None:
    """Runs until the socket dies. Starlette raises RuntimeError for a send after close."""
    try:
        while True:
            event = await subscription.get()
            await websocket.send_json({"type": "event", "data": event.model_dump(mode="json")})
    except (WebSocketDisconnect, RuntimeError):
        return


async def _receive_commands(websocket: WebSocket, subscription: Subscription) -> None:
    """Bad messages are ignored: a confused client shouldn't lose its stream."""
    try:
        while True:
            try:
                message = json.loads(await websocket.receive_text())
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif message.get("type") == "subscribe":
                session_id = message.get("session_id")
                subscription.session_id = session_id if isinstance(session_id, str) else None
    except WebSocketDisconnect:
        return


async def serve_client(websocket: WebSocket, subscription: Subscription) -> None:
    """Run both directions until either ends.

    A task group guarantees neither is left running. Starlette cancels through anyio, and mixing
    that with plain asyncio tasks leaks them and lets the cancellation escape.
    """
    async with anyio.create_task_group() as group:

        async def run_then_stop(direction: Direction) -> None:
            await direction(websocket, subscription)
            group.cancel_scope.cancel()

        group.start_soon(run_then_stop, _send_events)
        group.start_soon(run_then_stop, _receive_commands)


@router.websocket("/v1/stream")
async def stream(websocket: WebSocket, session_id: str | None = None) -> None:
    state = get_state(websocket)
    origin = websocket.headers.get("origin")
    # CORS doesn't apply to WebSockets, so any website could connect without this check.
    # Non-browser clients send no Origin.
    if origin is not None and origin not in allowed_origins(state.settings.dashboard_port):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    with state.bus.subscribe(session_id) as subscription:
        await serve_client(websocket, subscription)
