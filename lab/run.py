"""Runs scenarios and records judged outcomes.

uv run python -m lab.run --scenario A08 --shield off
uv run python -m lab.run --all --repeats 1 --shield off
"""

import argparse
import asyncio
import json
import re
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

import httpx
import structlog
from langchain_core.language_models import BaseChatModel

from lab.agent.preflight import check_agent_model
from lab.agent.victim import (
    AgentResult,
    AgentStep,
    LoadedTools,
    build_chat_model,
    open_tools,
    run_agent,
    step_event,
    system_prompt,
)
from lab.fixtures.runs import RunPaths, create_run, load_canaries
from lab.judge import Environment, judge
from lab.mcp_servers.common import LOOPBACK_ADDRESS
from lab.scenario import Scenario, load_scenarios
from lab.shielded import open_shielded_tools
from promptshield.config import Settings, get_settings
from promptshield.events import EventBus
from promptshield.layers.canary import CanaryStore
from promptshield.logs import configure_logging
from promptshield.models import (
    AutoApprove,
    Decision,
    Event,
    LabRunOutcome,
    SessionInfo,
    new_id,
)
from promptshield.provenance import git_description, machine_description
from promptshield.redact import Redactor
from promptshield.sdk import LocalShield
from promptshield.storage.db import Database

logger = structlog.get_logger(__name__)

RESULTS_FILE = "lab_runs.jsonl"
SERVICE_START_ATTEMPTS = 150
SERVICE_POLL_SECONDS = 0.2
CLEANUP_GRACE_SECONDS = 60.0
SAFE_LABEL = re.compile(r"[A-Za-z0-9_-]{1,40}")


def _sink_url(settings: Settings) -> str:
    return f"http://{LOOPBACK_ADDRESS}:{settings.sink_port}/captured"


def _site_url(settings: Settings) -> str:
    return f"http://{LOOPBACK_ADDRESS}:{settings.attack_site_port}/b01_article.html"


def _is_up(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2, trust_env=False).status_code == 200
    except httpx.HTTPError:
        return False


def _start_service(module: str, url: str) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [sys.executable, "-m", module], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for _ in range(SERVICE_START_ATTEMPTS):
        if _is_up(url):
            return process
        time.sleep(SERVICE_POLL_SECONDS)
    process.terminate()
    raise RuntimeError(f"{module} did not start")


@asynccontextmanager
async def lab_services(settings: Settings) -> AsyncIterator[None]:
    """Start the site and sink if needed, and stop only what was started here."""
    wanted = {
        "lab.attack_site.serve": _site_url(settings),
        "lab.attacker_sink.server": _sink_url(settings),
    }
    started = [
        await asyncio.to_thread(_start_service, module, url)
        for module, url in wanted.items()
        if not _is_up(url)
    ]
    try:
        yield
    finally:
        for process in started:
            process.terminate()
        for process in started:
            process.wait(timeout=10)


def _read_sink(settings: Settings) -> list[str]:
    response = httpx.get(_sink_url(settings), timeout=5, trust_env=False)
    response.raise_for_status()
    return [f"{entry['path']}?{entry['query']}\n{entry['body']}" for entry in response.json()]


def _observe(paths: RunPaths, settings: Settings, answer: str) -> Environment:
    return Environment(
        sink_texts=_read_sink(settings),
        outbox=json.loads(paths.outbox.read_text(encoding="utf-8")),
        sandbox_files={path.name for path in paths.sandbox.iterdir()},
        final_answer=answer,
        canaries=load_canaries(paths).values(),
    )


def _shown_to_user(result: AgentResult) -> str:
    """Everything the agent said in the final session, because the user sees all of it."""
    return "\n".join(step.text for step in result.steps if step.kind == "assistant")


def _root_cause(error: BaseException) -> BaseException:
    """Errors inside MCP sessions arrive wrapped in exception groups."""
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


class Runner:
    """Runs one scenario at a time and records the outcome."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        bus: EventBus,
        model: BaseChatModel | None = None,
        shield: LocalShield | None = None,
        auto_approve: AutoApprove | None = "deny",
    ) -> None:
        """With a shield, every run goes through the gateway. Unanswered approvals are denied by
        default, as the policy's timeout would."""
        self._settings = settings
        self._database = database
        self._bus = bus
        self._model = model or build_chat_model(settings)
        self._shield = shield
        self._auto_approve = auto_approve
        self._git = git_description()
        self._machine = machine_description()

    async def _session(
        self,
        scenario: Scenario,
        paths: RunPaths,
        task: str,
        steps: list[AgentStep],
        session_id: str,
    ) -> AgentResult:
        async def on_step(step: AgentStep) -> None:
            steps.append(step)
            await self._bus.publish(step_event(step, session_id))

        async with self._tools(scenario, paths, session_id) as loaded:
            return await run_agent(
                task,
                self._model,
                loaded,
                system_prompt(paths),
                max_tool_rounds=self._settings.agent_max_tool_rounds,
                on_step=on_step,
            )

    def _tools(
        self, scenario: Scenario, paths: RunPaths, session_id: str
    ) -> AbstractAsyncContextManager[LoadedTools]:
        if self._shield is None:
            return open_tools(paths, scenario.servers, scenario.evil_mode)
        return open_shielded_tools(paths, scenario, self._shield, session_id, self._auto_approve)

    async def _execute(
        self, scenario: Scenario, paths: RunPaths, steps: list[AgentStep], session_id: str
    ) -> AgentResult:
        if scenario.warmup_task:
            await self._session(scenario, paths, scenario.warmup_task, steps, session_id)
        return await self._session(scenario, paths, scenario.user_task, steps, session_id)

    async def run(
        self,
        scenario: Scenario,
        repeat: int = 0,
        batch: str = "",
        run_id: str | None = None,
        session_id: str | None = None,
    ) -> LabRunOutcome:
        """Run and judge. The environment is judged even after a crash or timeout, because the
        attack may already have happened. If judging fails, the result is unknown, not safe."""
        settings = self._settings
        run_id = run_id or new_id()
        paths = create_run(settings.lab_runs_dir, run_id, with_attacks=scenario.attack)
        shielded = self._shield is not None
        canaries = list(load_canaries(paths).values())
        # Masked in stored and shown events with or without the shield: a shield-off run is the one
        # most likely to leak them, and its timeline is still stored and shown.
        CanaryStore(self._bus.redactor).add(canaries)
        if self._shield is not None:
            self._shield.canaries.add(canaries)
        session = SessionInfo(user_task=scenario.user_task, run_id=run_id, shield=shielded)
        if session_id is not None:
            session.id = session_id
        await asyncio.to_thread(self._database.save_session, session)
        await self._bus.publish(Event(session_id=session.id, type="session_start"))

        steps: list[AgentStep] = []
        answer, status, error = "", "error", None
        started = perf_counter()
        task = asyncio.create_task(self._execute(scenario, paths, steps, session.id))
        # A plain wait, because errors and cancellation from MCP sessions arrive as exception
        # groups, which `asyncio.timeout` can't recognize. A run must never hang forever.
        done, _ = await asyncio.wait({task}, timeout=settings.scenario_timeout_seconds)
        if not done:
            status = "timeout"
            task.cancel()
            await asyncio.wait({task}, timeout=CLEANUP_GRACE_SECONDS)
        elif (failure := task.exception()) is not None:
            error = type(_root_cause(failure)).__name__
            logger.error("scenario_failed", scenario=scenario.id, error=error)
        else:
            result = task.result()
            answer, status = _shown_to_user(result), result.stopped
        latency_ms = (perf_counter() - started) * 1000

        outcome = LabRunOutcome.model_validate(
            {
                "run_id": run_id,
                "session_id": session.id,
                "scenario_id": scenario.id,
                "category": scenario.category,
                "batch": batch,
                "attack": scenario.attack,
                "shield": shielded,
                "repeat": repeat,
                "status": status,
                "error": error,
                "latency_ms": latency_ms,
                "steps": len(steps),
                "agent_model": settings.agent_model,
                "num_ctx": settings.num_ctx,
                "think": settings.think,
                "git": self._git,
                "machine": self._machine,
            }
        )
        try:
            environment = await asyncio.to_thread(_observe, paths, settings, answer)
            judgement = judge(scenario, environment)
            outcome = outcome.model_copy(update=judgement.model_dump())
        except Exception as failure:
            logger.error("judging_failed", scenario=scenario.id, error=type(failure).__name__)
            outcome = outcome.model_copy(update={"error": "judging_failed"})

        if shielded:
            blocked = await asyncio.to_thread(_blocking_rules, self._database, session.id)
            outcome = outcome.model_copy(update={"blocked_by": blocked})
        await self._bus.publish(Event(session_id=session.id, type="session_end"))
        await asyncio.to_thread(self._database.save_lab_run, outcome)
        _append_result(settings.reports_dir / RESULTS_FILE, outcome)
        return outcome


def _blocking_rules(database: Database, session_id: str) -> list[str]:
    """The rules behind everything that stopped, cleaned or held something back in this run."""
    acting = {Decision.BLOCK, Decision.SANITIZE, Decision.REQUIRE_APPROVAL}
    rules: dict[str, None] = {}
    for event in database.list_events(session_id=session_id, limit=1000):
        if event.verdict is not None and event.verdict.decision in acting:
            rules.update(dict.fromkeys(finding.rule_id for finding in event.verdict.findings))
        elif event.type == "registry_alert":  # tools the registry guard hid from this session
            rules.update(dict.fromkeys(str(rule) for rule in event.payload.get("rules", [])))
    return sorted(rules)


def _append_result(path: Path, outcome: LabRunOutcome) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(outcome.model_dump_json() + "\n")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run lab scenarios.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--scenario", action="append", help="scenario id, can repeat")
    target.add_argument("--all", action="store_true", help="every scenario")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--shield", choices=["off", "on"], default="off")
    parser.add_argument("--label", default="manual", help="prefix for this batch of runs")
    parser.add_argument(
        "--auto-approve",
        choices=["deny", "approve"],
        default="deny",
        help="answer for calls that need approval (shield on); deny matches the policy timeout",
    )
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be at least 1")
    if not SAFE_LABEL.fullmatch(args.label):
        parser.error("--label may only use letters, digits, - and _")
    return args


def batch_name(label: str) -> str:
    return f"{label}_{datetime.now(UTC):%Y%m%d_%H%M}"


def select(scenarios: dict[str, Scenario], args: argparse.Namespace) -> list[Scenario]:
    if args.all:
        return list(scenarios.values())
    unknown = set(args.scenario) - set(scenarios)
    if unknown:
        raise SystemExit(f"unknown scenarios: {sorted(unknown)}")
    return [scenarios[scenario_id] for scenario_id in args.scenario]


def _summary_line(outcome: LabRunOutcome) -> str:
    attack = {True: "SUCCEEDED", False: "failed", None: "UNKNOWN"}[outcome.attack_result]
    label = f"attack {attack}" if outcome.attack else "benign"
    return (
        f"{outcome.scenario_id:7} {label:17} utility={outcome.utility_ok!s:5} "
        f"{outcome.status:10} {outcome.steps:2} steps {outcome.latency_ms / 1000:6.1f}s "
        f"{','.join(outcome.conditions_met)}"
    )


async def _main(args: argparse.Namespace) -> None:
    settings = get_settings()
    configure_logging(settings.log_format)
    scenarios = select(load_scenarios(settings), args)
    await check_agent_model(settings)
    shield: LocalShield | None = None
    if args.shield == "on":
        shield = LocalShield.create(settings)
        await shield.warmup()
        database, bus = shield.state.database, shield.state.bus
    else:
        redactor = Redactor(settings.event_text_limit)
        database = Database(settings.db_path, redactor)
        bus = EventBus(database, redactor, settings.event_queue_size)
    runner = Runner(settings, database, bus, shield=shield, auto_approve=args.auto_approve)
    batch = batch_name(args.label)
    print(f"batch {batch} shield {args.shield}", flush=True)
    try:
        async with lab_services(settings):
            for repeat in range(args.repeats):
                for scenario in scenarios:
                    outcome = await runner.run(scenario, repeat, batch)
                    print(_summary_line(outcome), flush=True)
    finally:
        database.close()


if __name__ == "__main__":
    asyncio.run(_main(parse_args()))
