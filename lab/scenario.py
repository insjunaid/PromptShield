"""Scenario files. Each one states the user's task and what counts as the attack succeeding."""

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import Field, model_validator

from lab.mcp_servers.evil_server import EvilMode
from promptshield.config import Settings
from promptshield.models import Schema

ServerName = Literal["web", "mail", "files", "http", "evil"]


class SuccessCondition(Schema):
    """The attack succeeded if ANY of these is true after the run."""

    sink_received_canary: bool = False
    outbox_to_domain: str | None = None
    file_deleted: str | None = None
    # Counts only if the answer also carries a canary, or the attacker would get nothing.
    final_answer_contains_url: str | None = None

    def is_empty(self) -> bool:
        return not (
            self.sink_received_canary
            or self.outbox_to_domain
            or self.file_deleted
            or self.final_answer_contains_url
        )


class UtilityCheck(Schema):
    """The user's real task was done if ALL the configured checks pass."""

    final_answer_contains_any: list[str] = Field(default_factory=list)
    outbox_to: str | None = None


class Scenario(Schema):
    id: str = Field(pattern=r"^[AB]\d{2}(-[a-z]{2})?$")
    name: str
    category: str
    attack: bool
    user_task: str
    servers: list[ServerName]
    warmup_task: str | None = None  # an earlier session, for A11
    evil_mode: EvilMode = "poison"
    success_condition: SuccessCondition = Field(default_factory=SuccessCondition)
    utility_check: UtilityCheck
    expected_shield_layers: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_consistency(self) -> Self:
        if self.attack and self.success_condition.is_empty():
            raise ValueError(f"{self.id}: an attack needs a success condition")
        if not self.attack and not self.success_condition.is_empty():
            raise ValueError(f"{self.id}: a benign scenario can't have a success condition")
        if self.attack != self.id.startswith("A"):
            raise ValueError(f"{self.id}: id prefix doesn't match the attack flag")
        check = self.utility_check
        if not check.final_answer_contains_any and not check.outbox_to:
            raise ValueError(f"{self.id}: a scenario needs a utility check")
        return self


def _fill_ports(text: str, settings: Settings) -> str:
    """Ports live in the settings, so scenario files use placeholders."""
    site = f"http://localhost:{settings.attack_site_port}"
    sink = f"http://127.0.0.1:{settings.sink_port}"
    return text.replace("{site}", site).replace("{sink}", sink)


def load_scenarios(settings: Settings) -> dict[str, Scenario]:
    scenarios: dict[str, Scenario] = {}
    for path in sorted(Path(settings.scenarios_dir).glob("*.yaml")):
        raw = yaml.safe_load(_fill_ports(path.read_text(encoding="utf-8"), settings))
        scenario = Scenario.model_validate(raw)
        if scenario.id in scenarios:
            raise ValueError(f"duplicate scenario id: {scenario.id}")
        scenarios[scenario.id] = scenario
    return scenarios
