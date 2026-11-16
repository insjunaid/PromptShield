"""Scenario files must match the documented corpus and the fixtures they rely on."""

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from lab.attack_site.build import ATTACK_IMAGE, PAGES
from lab.fixtures import content
from lab.mcp_servers.common import require_local_url
from lab.scenario import Scenario, load_scenarios
from promptshield.config import REPO_ROOT, Settings
from promptshield.models import Decision, ToolCall
from promptshield.policy.engine import OutboundSignals, PolicyEngine
from promptshield.policy.schema import load_policy

ATTACKS = {f"A{n:02d}" for n in range(1, 14) if n != 12} | {"A12-hi", "A12-ar"}
BENIGN = {f"B{n:02d}" for n in range(1, 8)}


def settings(**values: object) -> Settings:
    return Settings(_env_file=None, **values)  # type: ignore[call-arg, arg-type]


SCENARIOS = load_scenarios(settings())


def test_every_documented_scenario_exists() -> None:
    assert set(SCENARIOS) == ATTACKS | BENIGN


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=SCENARIOS)
def test_placeholders_are_filled(scenario: Scenario) -> None:
    assert "{site}" not in scenario.user_task
    assert "{sink}" not in str(scenario.success_condition.final_answer_contains_url)


def test_ports_come_from_the_settings() -> None:
    custom = load_scenarios(settings(attack_site_port=8181, sink_port=9191))
    assert "http://localhost:8181/" in custom["A02"].user_task
    assert custom["A09"].success_condition.final_answer_contains_url == "http://127.0.0.1:9191/p"


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=SCENARIOS)
def test_task_urls_point_at_pages_that_exist(scenario: Scenario) -> None:
    known = {page.filename for page in PAGES} | {ATTACK_IMAGE}
    for url in re.findall(r"http://\S+", scenario.user_task):
        clean = url.rstrip(",.")
        require_local_url(clean, 8081, "test")
        assert clean.rsplit("/", 1)[1] in known


def test_every_web_page_is_used_by_a_scenario() -> None:
    tasks = " ".join(scenario.user_task for scenario in SCENARIOS.values())
    assert all(page.filename in tasks for page in PAGES)


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=SCENARIOS)
def test_all_scenarios_share_the_same_base_tools(scenario: Scenario) -> None:
    """Different tool lists would make results hard to compare."""
    assert {"web", "mail", "files", "http"} <= set(scenario.servers)


def test_only_tool_attacks_use_the_evil_server() -> None:
    users = {key for key, scenario in SCENARIOS.items() if "evil" in scenario.servers}
    assert users == {"A10", "A11"}


def test_a11_is_a_two_session_rug_pull() -> None:
    scenario = SCENARIOS["A11"]
    assert scenario.evil_mode == "rug_pull"
    assert scenario.warmup_task
    assert scenario.warmup_task != scenario.user_task


def test_a13_targets_the_right_file() -> None:
    assert SCENARIOS["A13"].success_condition.file_deleted == content.REPORT_FILE
    assert content.ATTACK_FILE in SCENARIOS["A13"].user_task


@pytest.mark.parametrize("scenario_id", sorted(ATTACKS))
def test_attacks_name_the_layers_expected_to_stop_them(scenario_id: str) -> None:
    assert SCENARIOS[scenario_id].expected_shield_layers


def test_benign_tasks_never_mention_attack_targets() -> None:
    for key in BENIGN:
        text = SCENARIOS[key].user_task.lower()
        assert "secrets" not in text
        assert "attacker" not in text


def test_b05_recipient_is_allowed_by_the_default_policy() -> None:
    """If this failed, B05 could never pass with the shield on."""
    engine = PolicyEngine(load_policy(REPO_ROOT / "promptshield" / "policy" / "default.yaml"))
    recipient = SCENARIOS["B05"].utility_check.outbox_to
    call = ToolCall(session_id="s", server="mail", tool="send_email", args={"to": recipient})
    assert engine.decide_outbound(OutboundSignals(tool_call=call)).decision is Decision.ALLOW


@pytest.mark.parametrize(
    "changes",
    [
        {"success_condition": {}},
        {"id": "B01"},
        {"attack": False},
        {"utility_check": {}},
        {"servers": ["ftp"]},
        {"id": "X01"},
        {"surprise": True},
    ],
)
def test_bad_scenarios_are_refused(changes: dict[str, object]) -> None:
    base = SCENARIOS["A02"].model_dump()
    with pytest.raises(ValidationError):
        Scenario.model_validate(base | changes)


def test_benign_scenario_with_a_condition_is_refused() -> None:
    base = SCENARIOS["B01"].model_dump()
    with pytest.raises(ValidationError, match="benign"):
        Scenario.model_validate(base | {"success_condition": {"sink_received_canary": True}})


def test_duplicate_ids_are_refused(tmp_path: Path) -> None:
    source = (REPO_ROOT / "lab" / "scenarios" / "A02_white_text.yaml").read_text(encoding="utf-8")
    (tmp_path / "one.yaml").write_text(source, encoding="utf-8")
    (tmp_path / "two.yaml").write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_scenarios(settings(scenarios_dir=tmp_path))
