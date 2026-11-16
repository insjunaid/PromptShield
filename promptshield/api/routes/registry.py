"""The tool registry: what each upstream offers, and a human's approval of a held-back tool."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AwareDatetime

from promptshield.api.auth import require_admin
from promptshield.api.state import AppState, get_state
from promptshield.models import Event, Finding, Schema, ToolPin, ToolStatus

router = APIRouter()


class RegistryTool(Schema):
    server: str
    tool: str
    sha256: str
    status: ToolStatus
    pinned_sha256: str | None = None
    pinned_updated: AwareDatetime | None = None
    # Untrusted text from the upstream server: shown as plain text, never as markup.
    description: str = ""
    findings: list[Finding]


@router.get("/v1/registry/tools")
async def list_tools(state: Annotated[AppState, Depends(get_state)]) -> list[RegistryTool]:
    pins = {(pin.server, pin.tool): pin for pin in state.database.list_pins()}
    return [
        RegistryTool(
            server=item.server,
            tool=item.tool.name,
            sha256=item.sha256,
            status=item.status,
            pinned_sha256=pin.sha256 if (pin := pins.get((item.server, item.tool.name))) else None,
            pinned_updated=pin.updated if pin else None,
            description=state.redactor.scrub_text(item.tool.description or ""),
            findings=item.findings,
        )
        for item in state.registry_guard.current()
    ]


@router.post("/v1/registry/tools/{server}/{tool}/approve", dependencies=[Depends(require_admin)])
async def approve_tool(
    server: str, tool: str, state: Annotated[AppState, Depends(get_state)]
) -> ToolPin:
    """Pins the tool as it is now. It shows again from the next tool listing."""
    pin = state.registry_guard.approve(server, tool)
    if pin is None:
        raise HTTPException(status_code=404, detail="no such tool has been seen")
    await state.bus.publish(
        Event(type="registry_alert", tool=f"{server}.{tool}", payload={"status": "approved"})
    )
    return pin
