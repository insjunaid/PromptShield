"""Shared schemas for everything that crosses a boundary.

Tool output is attacker-controlled and these models sit on that path, so they validate strictly:
unknown fields are rejected, scores stay in range and binary content must really be base64.
"""

import base64
import binascii
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ulid import ULID

MAX_EVIDENCE_CHARS = 200

# L3 reports a clean page with this rule, so the policy can tell "benign" from "didn't run".
JUDGE_BENIGN_RULE = "L3.JUDGE.benign"

LayerName = Literal["L0", "L1", "L2", "L3", "CANARY", "L4", "REGISTRY"]
LayerStatus = Literal["ran", "skipped", "error"]
ContentKind = Literal["text", "html", "image", "json"]
AutoApprove = Literal["approve", "deny"]
ApprovalStatus = Literal["pending", "approved", "denied", "timed_out"]
ToolStatus = Literal["trusted", "flagged", "quarantined"]
SegmentOrigin = Literal[
    "visible",
    "hidden_css",
    "html_comment",
    "attribute",
    "meta",
    "hidden_markup",
    "zero_width",
    "unicode_tag",
    "decoded_payload",
    "ocr",
    "tool_description",
]
EventType = Literal[
    "tool_call",
    "tool_result",
    "verdict",
    "approval_requested",
    "approval_resolved",
    "canary_tripped",
    "registry_alert",
    "session_start",
    "session_end",
    "agent_message",
    "policy_changed",
]


def new_id() -> str:
    """Return a ULID, so ids sort by creation time without a separate timestamp column."""
    return str(ULID())


def utc_now() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Order for comparisons, because string order would put CRITICAL below INFO."""
        return list(Severity).index(self)


class Decision(StrEnum):
    """Values match the policy YAML, so forced rules parse straight into this enum."""

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        """Order for the "most severe outcome wins" rule in the policy engine."""
        return list(Decision).index(self)


class Direction(StrEnum):
    INBOUND = "INBOUND"  # tool result
    OUTBOUND = "OUTBOUND"  # tool call


class TrustLabel(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class Schema(BaseModel):
    """Base for all schemas. Rejecting unknown fields makes malformed input fail loudly."""

    model_config = ConfigDict(extra="forbid")


class ContentItem(Schema):
    """One piece of tool output. Binary data is base64 so items stay valid JSON."""

    kind: ContentKind
    data: str
    data_is_base64: bool = False
    source: str
    mime: str | None = None

    @model_validator(mode="after")
    def check_encoding(self) -> Self:
        if self.kind == "image" and not self.data_is_base64:
            raise ValueError("image content must be base64 encoded")
        if self.data_is_base64:
            try:
                base64.b64decode(self.data, validate=True)
            except binascii.Error as error:
                raise ValueError("data is not valid base64") from error
        return self

    def raw_bytes(self) -> bytes:
        """Return the original bytes, for layers such as OCR that need them."""
        if self.data_is_base64:
            return base64.b64decode(self.data, validate=True)
        return self.data.encode("utf-8")


class Segment(Schema):
    """A piece of extracted text, tagged with where it came from. Produced by L0."""

    text: str
    origin: SegmentOrigin
    encoding: str | None = None  # for decoded_payload: base64, hex, url, rot13
    offset: int | None = None
    original: str | None = None  # the text before cleaning, kept as evidence if it changed
    hidden_by: Literal["display_none", "tiny_font", "color_match", "offscreen"] | None = None


class Finding(Schema):
    layer: LayerName
    rule_id: str
    title: str
    severity: Severity
    score: float = Field(ge=0, le=1)
    evidence: str
    segment_origin: SegmentOrigin | None = None
    latency_ms: float = Field(ge=0)

    @field_validator("evidence")
    @classmethod
    def truncate_evidence(cls, value: str) -> str:
        """Cap evidence so attacker-sized text can't flood storage or the dashboard."""
        if len(value) <= MAX_EVIDENCE_CHARS:
            return value
        return value[: MAX_EVIDENCE_CHARS - 1] + "…"


class ToolCall(Schema):
    session_id: str
    tool: str
    server: str
    args: dict[str, Any]


class SessionInfo(Schema):
    """Session state. user_task is None for clients that don't pass it, since MCP never does."""

    id: str = Field(default_factory=new_id)
    started: AwareDatetime = Field(default_factory=utc_now)
    user_task: str | None = None
    history_summary: str | None = None
    run_id: str | None = None
    shield: bool = True
    auto_approve: AutoApprove | None = None


class Approval(Schema):
    id: str = Field(default_factory=new_id)
    session_id: str
    tool_call: ToolCall
    reasons: list[str]
    created: AwareDatetime = Field(default_factory=utc_now)
    expires: AwareDatetime
    status: ApprovalStatus = "pending"

    @model_validator(mode="after")
    def check_expiry(self) -> Self:
        if self.expires <= self.created:
            raise ValueError("expires must be after created")
        return self


class ToolPin(Schema):
    """The approved fingerprint of a tool definition, used to detect rug pulls."""

    server: str
    tool: str
    sha256: str
    status: ToolStatus = "trusted"
    updated: AwareDatetime = Field(default_factory=utc_now)


INTERRUPTED_STATUSES = frozenset({"timeout", "error"})


class LabRunOutcome(Schema):
    """The judged result of one lab run.

    `attack_succeeded` is what the judge saw, and is None if judging itself failed. Reports read
    `attack_result`, which also accounts for how the run ended.
    """

    run_id: str
    session_id: str
    scenario_id: str
    category: str = ""
    batch: str = ""
    attack: bool
    shield: bool
    repeat: int = 0
    status: Literal["finished", "step_limit", "timeout", "error"]
    error: str | None = None
    attack_succeeded: bool | None = None
    conditions_met: list[str] = Field(default_factory=list)
    utility_ok: bool | None = None
    blocked_by: list[str] = Field(default_factory=list)
    latency_ms: float = Field(default=0.0, ge=0)
    steps: int = 0
    agent_model: str
    num_ctx: int
    think: bool
    git: str = "unknown"
    machine: str = "unknown"
    started: AwareDatetime = Field(default_factory=utc_now)

    @property
    def attack_result(self) -> bool | None:
        """No evidence from a run that died proves nothing: the attack might have landed had the
        run gone on. Counting it as failed would credit a crash to the defense. Evidence found
        before the crash still counts."""
        if self.attack_succeeded is False and self.status in INTERRUPTED_STATUSES:
            return None
        return self.attack_succeeded


class StatsBucket(Schema):
    """One slice of the window, for sparklines."""

    start: AwareDatetime
    scans: int = 0
    blocked: int = 0
    sanitized: int = 0
    p95_ms: float = 0.0


class StatsSnapshot(Schema):
    window: Literal["1h", "24h", "all"] = "1h"
    scans: int = 0
    blocked: int = 0
    sanitized: int = 0
    approvals_pending: int = 0
    canaries_tripped: int = 0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    findings_by_layer: dict[str, int] = Field(default_factory=dict)
    top_rules: dict[str, int] = Field(default_factory=dict)
    series: list[StatsBucket] = Field(default_factory=list)


class Verdict(Schema):
    decision: Decision  # what actually happened
    would_decision: Decision | None = None  # monitor mode: what enforce mode would have done
    risk_score: float = Field(ge=0, le=1)
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    sanitized_items: list[ContentItem] | None = None  # one per MCP content block
    segments: list[Segment] = Field(default_factory=list)  # for Attack Replay
    layers_run: dict[str, LayerStatus] = Field(default_factory=dict)
    total_latency_ms: float = Field(default=0.0, ge=0)


class Event(Schema):
    id: str = Field(default_factory=new_id)
    ts: AwareDatetime = Field(default_factory=utc_now)
    session_id: str | None = None  # None for registry and policy events
    type: EventType
    direction: Direction | None = None
    tool: str | None = None
    verdict: Verdict | None = None
    payload: dict[str, Any] = Field(default_factory=dict)  # redacted and truncated


class SessionSummary(Schema):
    """One row of the session list: what happened, without the timeline."""

    id: str
    started: AwareDatetime
    user_task: str | None = None
    run_id: str | None = None
    shield: bool = True
    events: int = 0
    findings: int = 0
    max_severity: Severity | None = None
    decisions: dict[str, int] = Field(default_factory=dict)
    lab_run: LabRunOutcome | None = None  # set for Red-Team Lab sessions


class SessionReplay(Schema):
    """A session's timeline for Attack Replay, oldest first. Verdicts hold segments and findings."""

    session: SessionSummary
    events: list[Event]
    truncated: bool = False  # true if only the newest events fit
