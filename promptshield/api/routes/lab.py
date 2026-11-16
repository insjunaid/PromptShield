"""The Red-Team Lab: run scenarios with and without the shield, and see what the attacker got.

The lab package is imported only when these routes are used, so the shield itself never depends on
it. Starting, pairing and resetting runs need the admin token.
"""

from typing import TYPE_CHECKING, Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.requests import Request

from promptshield.api.auth import require_admin
from promptshield.api.state import AppState, get_state
from promptshield.models import AutoApprove, Schema

if TYPE_CHECKING:
    from lab.jobs import LabJob, LabJobs

router = APIRouter()


class RunRequest(Schema):
    scenario_id: str
    shield: bool
    auto_approve: AutoApprove | None = "deny"


class PairRequest(Schema):
    scenario_id: str
    auto_approve: AutoApprove | None = "deny"


class ScenarioSummary(Schema):
    id: str
    name: str
    category: str
    attack: bool


class StartedRun(Schema):
    run_id: str
    session_id: str


def jobs(request: Request) -> Any:
    """Built on first use, so the lab loads only when the lab is used."""
    existing = getattr(request.app.state, "lab_jobs", None)
    if existing is None:
        from lab.jobs import LabJobs
        from promptshield.sdk import LocalShield

        state: AppState = request.app.state.shield
        existing = LabJobs(state.settings, LocalShield(state))
        request.app.state.lab_jobs = existing
    return existing


# Typed as Any for FastAPI: naming the lab's types here would import the lab at startup.
Jobs = Annotated[Any, Depends(jobs)]


def _scenario(lab: "LabJobs", scenario_id: str) -> Any:
    scenario = lab.scenarios().get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="unknown scenario")
    return scenario


def _started(job: "LabJob") -> StartedRun:
    return StartedRun(run_id=job.run_id, session_id=job.session_id)


@router.get("/v1/lab/scenarios")
async def list_scenarios(lab: Jobs) -> list[ScenarioSummary]:
    return [
        ScenarioSummary(id=item.id, name=item.name, category=item.category, attack=item.attack)
        for item in lab.scenarios().values()
    ]


@router.post("/v1/lab/run", dependencies=[Depends(require_admin)])
async def start_run(body: RunRequest, lab: Jobs) -> StartedRun:
    return _started(lab.submit(_scenario(lab, body.scenario_id), body.shield, body.auto_approve))


@router.post("/v1/lab/run-pair", dependencies=[Depends(require_admin)])
async def start_pair(body: PairRequest, lab: Jobs) -> list[StartedRun]:
    """Shield off, then on. Each run has its own sandbox, canaries and session."""
    scenario = _scenario(lab, body.scenario_id)
    return [_started(lab.submit(scenario, shield, body.auto_approve)) for shield in (False, True)]


@router.get("/v1/lab/runs/{run_id}")
async def run_status(
    run_id: str, lab: Jobs, state: Annotated[AppState, Depends(get_state)]
) -> dict[str, Any]:
    job = lab.get(run_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown run")
    # The sink holds stolen canaries, so the run's captures are redacted like everything else.
    snapshot: dict[str, Any] = state.redactor.scrub_value(job.model_dump(mode="json"))
    return snapshot


@router.get("/v1/lab/sink")
async def captured(state: Annotated[AppState, Depends(get_state)]) -> list[dict[str, Any]]:
    """What the attacker received. Redacted: it holds the stolen canaries."""
    url = f"http://127.0.0.1:{state.settings.sink_port}/captured"
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as error:
        raise HTTPException(status_code=503, detail="attacker sink is not running") from error
    entries: list[dict[str, Any]] = response.json()
    return [state.redactor.scrub_value(entry) for entry in entries]


@router.post("/v1/lab/reset", dependencies=[Depends(require_admin)])
async def reset(lab: Jobs) -> dict[str, str]:
    from lab.jobs import LabBusy

    try:
        await lab.reset()
    except LabBusy as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return {"status": "reset"}
