"""Claude Code's HTTP hooks: the plugin points PreToolUse and PostToolUse here.

An HTTP hook launches no process, so on Windows no console window flashes on every tool call (a
command hook started from a windowed app does), and nothing has to start up per call. Claude Code
treats a JSON reply like a command hook's output and an empty reply as "no opinion"; if the shield
isn't running, the request fails and Claude Code goes ahead, which is the plugin's intended
fail-open. The checks are the ones `promptshield hook` runs (hooks.py), done in-process, so the
verdicts reach the dashboard like any other.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Response
from fastapi.responses import JSONResponse

from promptshield import hooks
from promptshield.api.routes.guard import guard_tool_call
from promptshield.api.routes.scan import ScanRequest, scan
from promptshield.api.state import AppState, get_state
from promptshield.models import ToolCall

router = APIRouter()


@router.post("/v1/hooks/claude", response_model=None)
async def claude_hook(
    event: Annotated[dict[str, Any], Body()], state: Annotated[AppState, Depends(get_state)]
) -> Response:
    verdicts: dict[str, dict[str, Any]] = {}

    async def run(path: str, body: dict[str, Any]) -> None:
        if path == "/v1/guard/tool-call":
            verdict = await guard_tool_call(ToolCall.model_validate(body), state)
        else:
            verdict = await scan(ScanRequest.model_validate(body), state)
        verdicts[path] = verdict.model_dump(mode="json")

    # hooks.handle asks for each check through a (synchronous) callback: a first pass records which
    # checks it wants, they run here, and a second pass turns their verdicts into the answer.
    requests: list[tuple[str, dict[str, Any]]] = []

    def record(path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        requests.append((path, body))
        return None

    hooks.handle(event, record)
    for path, body in requests:
        await run(path, body)
    answer = hooks.handle(event, lambda path, _: verdicts.get(path))
    if answer is None:
        return Response(status_code=200)  # empty body: no opinion
    return JSONResponse(answer)
