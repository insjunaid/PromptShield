"""The policy file's shape. A bad policy is refused when loaded, never half-applied."""

import re
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import ConfigDict, Field, field_validator, model_validator

from promptshield.models import Decision, LayerName, Schema
from promptshield.policy.destinations import parse_host_entry

ToolClass = Literal["read", "write", "egress"]
FailMode = Literal["open", "closed"]
OutboundAction = Literal["REQUIRE_APPROVAL", "BLOCK"]

TOOL_KEY = re.compile(r"^[\w-]+\.[\w-]+$")


class FailModes(Schema):
    content_scan: FailMode = "closed"
    action_guard: FailMode = "closed"


class Thresholds(Schema):
    sanitize: float = Field(default=0.35, ge=0, le=1)
    block: float = Field(default=0.75, ge=0, le=1)
    judge_band: tuple[float, float] = (0.30, 0.80)
    judge_benign_discount: float = Field(default=0.5, ge=0, le=1)

    @model_validator(mode="after")
    def check_order(self) -> Self:
        if self.sanitize >= self.block:
            raise ValueError("sanitize threshold must be below block threshold")
        low, high = self.judge_band
        if not 0 <= low < high <= 1:
            raise ValueError("judge_band must be two rising values within 0..1")
        return self


class Weights(Schema):
    L0: float = Field(default=0.3, ge=0)
    L1: float = Field(default=1.0, ge=0)
    L2: float = Field(default=0.8, ge=0)
    L3: float = Field(default=0.9, ge=0)
    CANARY: float = Field(default=1.0, ge=0)
    L4: float = Field(default=1.0, ge=0)
    REGISTRY: float = Field(default=1.0, ge=0)
    hidden_origin_boost: float = Field(default=1.3, ge=1)

    def for_layer(self, layer: LayerName) -> float:
        weight: float = getattr(self, layer)
        return weight


class ToolPolicy(Schema):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    tool_class: ToolClass = Field(alias="class")
    sensitive_output: bool = False
    require_approval: bool = False
    arg_destination: str | None = None
    egress_if: Literal["has_query"] | None = None


class EgressPolicy(Schema):
    allow_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)
    allow_recipients: list[str] = Field(default_factory=list)
    unknown_destination: OutboundAction = "REQUIRE_APPROVAL"
    after_high_finding: OutboundAction = "REQUIRE_APPROVAL"
    sensitive_data_to_unknown: OutboundAction = "BLOCK"
    max_egress_per_session: int = Field(default=5, ge=0)
    max_identical_calls: int = Field(default=3, ge=1)

    @field_validator("allow_hosts", "deny_hosts")
    @classmethod
    def check_host_entries(cls, value: list[str]) -> list[str]:
        for entry in value:
            parse_host_entry(entry)
        return value


class ApprovalPolicy(Schema):
    timeout_seconds: float = Field(default=120, gt=0)
    on_timeout: Literal["BLOCK"] = "BLOCK"


class SanitizePolicy(Schema):
    datamarking: bool = True
    marker: str = Field(default="^", min_length=1)


class Policy(Schema):
    version: Literal[1] = 1
    mode: Literal["enforce", "monitor"] = "enforce"
    fail_mode: FailModes = Field(default_factory=FailModes)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    weights: Weights = Field(default_factory=Weights)
    force: dict[str, Decision] = Field(default_factory=dict)
    default_tool_class: ToolClass = "egress"
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    egress: EgressPolicy = Field(default_factory=EgressPolicy)
    approvals: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    sanitize: SanitizePolicy = Field(default_factory=SanitizePolicy)
    # A visible L1 hit with no other strong evidence: an article quoting an attack looks the same
    # to a classifier as the attack (D047). Null turns the cap off.
    lone_visible_classifier: Decision | None = Decision.SANITIZE

    @field_validator("force")
    @classmethod
    def check_forced_decisions(cls, value: dict[str, Decision]) -> dict[str, Decision]:
        """A forced ALLOW would let one rule id switch detection off."""
        for rule_id, decision in value.items():
            if decision not in (Decision.SANITIZE, Decision.BLOCK):
                raise ValueError(f"force for {rule_id} must be SANITIZE or BLOCK")
        return value

    @field_validator("tools")
    @classmethod
    def check_tool_keys(cls, value: dict[str, ToolPolicy]) -> dict[str, ToolPolicy]:
        """Keys name the server too, so a shadowing tool can't inherit another tool's class."""
        for key in value:
            if not TOOL_KEY.match(key):
                raise ValueError(f"tool key must be server.tool, got {key!r}")
        return value


def load_policy(path: Path) -> Policy:
    return parse_policy(path.read_text(encoding="utf-8"))


def parse_policy(text: str) -> Policy:
    """Parse and validate YAML. `safe_load` matters: this text can arrive through the API."""
    return Policy.model_validate(yaml.safe_load(text))
