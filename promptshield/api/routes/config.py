"""Non-secret runtime settings, for the dashboard's mode pill and settings views."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends

from promptshield.api.state import AppState, get_state
from promptshield.models import LayerName, Schema

router = APIRouter()


class RuntimeConfig(Schema):
    mode: Literal["enforce", "monitor"]
    sanitize_threshold: float
    block_threshold: float
    judge_mode: Literal["off", "uncertain", "always"]
    enabled_layers: list[LayerName]
    agent_model: str
    judge_model: str


@router.get("/v1/config")
async def runtime_config(state: Annotated[AppState, Depends(get_state)]) -> RuntimeConfig:
    """Nothing here is secret: no tokens, paths or keys."""
    policy, settings = state.engine.policy, state.settings
    return RuntimeConfig(
        mode=policy.mode,
        sanitize_threshold=policy.thresholds.sanitize,
        block_threshold=policy.thresholds.block,
        judge_mode=settings.judge_mode,
        enabled_layers=settings.enabled_layers,
        agent_model=settings.agent_model,
        judge_model=settings.judge_model,
    )
