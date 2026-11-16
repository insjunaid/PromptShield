"""Lab runs started from the API, one at a time, in the background.

Runs share the API's own shield, so their events reach the dashboard live. They run one after
another: on CPU two agents at once would only slow both and blur the timings.
"""

import asyncio
import shutil
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from typing import Any, Literal

import httpx
import structlog
from pydantic import Field

from lab.agent.victim import build_chat_model
from lab.run import Runner, lab_services
from lab.scenario import Scenario, load_scenarios
from promptshield.config import Settings
from promptshield.models import AutoApprove, LabRunOutcome, Schema, new_id
from promptshield.sdk import LocalShield

logger = structlog.get_logger(__name__)

JobStatus = Literal["queued", "running", "finished", "failed"]
DASHBOARD_BATCH = "dashboard"
RunnerFactory = Callable[[bool, AutoApprove | None], Runner]
ServicesFactory = Callable[[Settings], AbstractAsyncContextManager[None]]
SinkReader = Callable[[Settings], Awaitable[list[dict[str, Any]]]]


async def read_sink(settings: Settings) -> list[dict[str, Any]]:
    """Everything the sink holds. A sink that isn't running has received nothing."""
    url = f"http://127.0.0.1:{settings.sink_port}/captured"
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.HTTPError:
        return []
    entries: list[dict[str, Any]] = response.json()
    return entries


class LabJob(Schema):
    run_id: str
    session_id: str
    scenario_id: str
    shield: bool
    status: JobStatus = "queued"
    outcome: LabRunOutcome | None = None
    # What the attacker's sink received during this run. Stored as sent: the API redacts it.
    captured: list[dict[str, Any]] = Field(default_factory=list)


class LabBusy(Exception):
    """Raised for a change that would disturb a run in progress."""


class LabJobs:
    def __init__(
        self,
        settings: Settings,
        shield: LocalShield,
        runner_factory: RunnerFactory | None = None,
        services: ServicesFactory = lab_services,
        sink: SinkReader = read_sink,
    ) -> None:
        """The factories exist for tests, which must not start real agents or servers."""
        self._settings = settings
        self._shield = shield
        self._factory = runner_factory or self._default_runner
        self._services = services
        self._sink = sink
        self._lock = asyncio.Lock()
        self._jobs: dict[str, LabJob] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    def scenarios(self) -> dict[str, Scenario]:
        return load_scenarios(self._settings)

    def get(self, run_id: str) -> LabJob | None:
        return self._jobs.get(run_id)

    @property
    def busy(self) -> bool:
        return any(job.status in ("queued", "running") for job in self._jobs.values())

    def submit(self, scenario: Scenario, shield: bool, auto_approve: AutoApprove | None) -> LabJob:
        job = LabJob(run_id=new_id(), session_id=new_id(), scenario_id=scenario.id, shield=shield)
        self._jobs[job.run_id] = job
        task = asyncio.create_task(self._run(job, scenario, auto_approve))
        self._tasks.add(task)  # held, or the task could be garbage collected mid-run
        task.add_done_callback(self._tasks.discard)
        return job

    async def reset(self) -> None:
        """Clears run folders and the sink log. Refused while a run is queued or going."""
        if self.busy:
            raise LabBusy("a lab run is in progress")
        runs = self._settings.lab_runs_dir
        if runs.exists():
            await asyncio.to_thread(shutil.rmtree, runs)
        url = f"http://127.0.0.1:{self._settings.sink_port}/captured"
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                await client.delete(url)
        except httpx.HTTPError:
            logger.info("sink_not_running")  # nothing to clear

    async def _run(self, job: LabJob, scenario: Scenario, auto_approve: AutoApprove | None) -> None:
        async with self._lock:
            job.status = "running"
            try:
                async with self._services(self._settings):
                    # Runs go one at a time, so whatever reaches the sink meanwhile is this run's.
                    before = len(await self._sink(self._settings))
                    runner = self._factory(job.shield, auto_approve)
                    # Labelled so these runs never mix with a benchmark batch in lab_runs.jsonl.
                    job.outcome = await runner.run(
                        scenario,
                        batch=DASHBOARD_BATCH,
                        run_id=job.run_id,
                        session_id=job.session_id,
                    )
                    job.captured = (await self._sink(self._settings))[before:]
                job.status = "finished"
            except Exception as error:
                logger.error("lab_job_failed", run_id=job.run_id, error=type(error).__name__)
                job.status = "failed"

    def _default_runner(self, shield: bool, auto_approve: AutoApprove | None) -> Runner:
        state = self._shield.state
        return Runner(
            self._settings,
            state.database,
            state.bus,
            build_chat_model(self._settings),
            shield=self._shield if shield else None,
            auto_approve=auto_approve,
        )
