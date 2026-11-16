"""The active policy: read it, replace it, or switch its mode. Changes hot-reload, need the token.

The YAML is saved exactly as written, comments included, so a dashboard save leaves the file as
readable as a hand edit. Mode changes edit the one `mode:` line for the same reason.
"""

import asyncio
import os
import re
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import Field, ValidationError

from promptshield.api.auth import require_admin
from promptshield.api.state import AppState, get_state
from promptshield.models import Event, Schema
from promptshield.policy.schema import Policy, parse_policy

router = APIRouter()

MAX_POLICY_CHARS = 65536
MODE_LINE = re.compile(r"^mode:[ \t]*[^\s#]*", re.MULTILINE)
# One save at a time, so two saves can't interleave their file writes and reloads.
_save_lock = asyncio.Lock()

State = Annotated[AppState, Depends(get_state)]


class PolicyDocument(Schema):
    yaml: str
    policy: dict[str, Any]
    file: str  # the file's name only: paths stay off the API


class PolicyUpdate(Schema):
    yaml: str = Field(max_length=MAX_POLICY_CHARS)


class ModeUpdate(Schema):
    mode: Literal["enforce", "monitor"]


class PolicyProblem(Schema):
    where: str  # "line 4" for YAML syntax, a dotted path such as "thresholds.block" otherwise
    message: str


def _problems(error: Exception) -> list[PolicyProblem]:
    if isinstance(error, ValidationError):
        return [
            PolicyProblem(
                where=".".join(str(part) for part in item["loc"]) or "policy", message=item["msg"]
            )
            for item in error.errors()
        ]
    mark = getattr(error, "problem_mark", None)
    where = f"line {mark.line + 1}" if mark is not None else "yaml"
    return [PolicyProblem(where=where, message=str(getattr(error, "problem", None) or error))]


class InvalidPolicy(Exception):
    def __init__(self, problems: list[PolicyProblem]) -> None:
        super().__init__("invalid policy")
        self.problems = problems


def _validate(text: str) -> Policy:
    try:
        return parse_policy(text)
    except (yaml.YAMLError, ValidationError) as error:
        raise InvalidPolicy(_problems(error)) from error


def _refusal(error: InvalidPolicy) -> JSONResponse:
    """The API's usual error shape, with every problem listed so the editor can show them all."""
    problems = [problem.model_dump() for problem in error.problems]
    body = {
        "code": "invalid_policy",
        "message": "The policy is not valid",
        "details": {"problems": problems},
    }
    return JSONResponse(status_code=422, content={"error": body})


def _write_atomically(path: Path, text: str) -> None:
    """Write beside the file, then swap it in, so a crash never leaves half a policy."""
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as file:
            file.write(text)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _document(state: AppState, text: str) -> PolicyDocument:
    return PolicyDocument(
        yaml=text,
        policy=state.engine.policy.model_dump(mode="json", by_alias=True),
        file=state.settings.policy_path.name,
    )


async def _save(state: AppState, text: str) -> PolicyDocument:
    policy = _validate(text)
    async with _save_lock:
        await asyncio.to_thread(_write_atomically, state.settings.policy_path, text)
        state.engine.reload(policy)  # the sanitizer reads the engine's policy, so it follows
    thresholds = policy.thresholds
    await state.bus.publish(
        Event(
            type="policy_changed",
            payload={
                "mode": policy.mode,
                "sanitize": thresholds.sanitize,
                "block": thresholds.block,
            },
        )
    )
    return _document(state, text)


def _read(state: AppState) -> str:
    return state.settings.policy_path.read_text(encoding="utf-8")


@router.get("/v1/policy")
async def get_policy(state: State) -> PolicyDocument:
    return _document(state, await asyncio.to_thread(_read, state))


@router.put("/v1/policy", dependencies=[Depends(require_admin)], response_model=PolicyDocument)
async def put_policy(body: PolicyUpdate, state: State) -> PolicyDocument | JSONResponse:
    """Invalid YAML or values are refused with 422 and a list of problems; nothing changes."""
    try:
        return await _save(state, body.yaml)
    except InvalidPolicy as error:
        return _refusal(error)


def with_mode(text: str, mode: str) -> str:
    """Change the top-level mode line, keeping its comment. Adds the line if there is none."""
    if MODE_LINE.search(text):
        return MODE_LINE.sub(f"mode: {mode}", text, count=1)
    return f"mode: {mode}\n{text}"


@router.post(
    "/v1/policy/mode", dependencies=[Depends(require_admin)], response_model=PolicyDocument
)
async def set_mode(body: ModeUpdate, state: State) -> PolicyDocument | JSONResponse:
    text = await asyncio.to_thread(_read, state)
    try:
        return await _save(state, with_mode(text, body.mode))
    except InvalidPolicy as error:  # the file on disk was already invalid
        return _refusal(error)
