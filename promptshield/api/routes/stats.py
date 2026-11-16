"""Dashboard KPIs for a time window."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends

from promptshield.api.state import AppState, get_state
from promptshield.models import StatsSnapshot
from promptshield.stats import StatsWindow, compute_stats

router = APIRouter()


@router.get("/v1/stats")
async def stats(
    state: Annotated[AppState, Depends(get_state)], window: StatsWindow = "1h"
) -> StatsSnapshot:
    return await asyncio.to_thread(compute_stats, state.database, window)
