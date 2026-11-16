"""Health check. Reports what's available so the dashboard can show it. Never shows secrets."""

from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends

from promptshield.api.state import AppState, get_state
from promptshield.models import Schema

OLLAMA_TIMEOUT_SECONDS = 2.0
# Built into the app rather than loaded into the layer registry, so they are ready once enabled.
BUILT_IN_LAYERS = frozenset({"L4", "REGISTRY"})

router = APIRouter()


class HealthResponse(Schema):
    status: Literal["ok"] = "ok"
    layers: dict[str, Literal["ready", "loading", "unavailable"]]
    models: dict[str, str]
    ollama: bool


async def ollama_reachable(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{url}/api/version")
    except httpx.HTTPError:
        return False
    return response.is_success


@router.get("/health")
async def health(state: Annotated[AppState, Depends(get_state)]) -> HealthResponse:
    settings = state.settings
    return HealthResponse(
        layers={
            name: "ready" if name in state.registry or name in BUILT_IN_LAYERS else "unavailable"
            for name in settings.enabled_layers
        },
        models={
            "agent": settings.agent_model,
            "judge": settings.judge_model,
            "classifier": settings.classifier_model,
        },
        ollama=await ollama_reachable(settings.ollama_url),
    )
