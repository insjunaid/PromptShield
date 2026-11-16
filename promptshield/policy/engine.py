"""Turns findings into a decision. Pure logic: it never calls a model or touches the network.

Inbound flow for the caller (the gateway):
    1. `pipeline.scan(...)`, with `should_judge` as the judge gate
    2. `decide_inbound(result)`
    3. if `wants_rescan(result)`: strip the page, scan it again, `decide_inbound(result, rescan)`
"""

from dataclasses import dataclass
from math import prod
from time import perf_counter
from urllib.parse import urlsplit

from pydantic import Field

from promptshield.models import (
    JUDGE_BENIGN_RULE,
    Decision,
    Finding,
    LayerStatus,
    Schema,
    Segment,
    Severity,
    ToolCall,
    Verdict,
)
from promptshield.pipeline import PipelineResult
from promptshield.policy.destinations import classify_destination
from promptshield.policy.schema import OutboundAction, Policy, ToolClass, ToolPolicy

MAX_REASONS = 3
NEVER_DOWNGRADE_PREFIXES = ("CANARY.", "REGISTRY.")
NO_ISSUES_REASON = "No issues found."
LAYER_FAILED_BLOCK_REASON = "A detection layer failed, so this was blocked as a precaution."
LAYER_FAILED_WARNING = "A detection layer failed, so this was not fully checked."
DOWNGRADED_REASON = "Hidden instructions were removed, and the remaining content scanned clean."
CAPPED_REASON = "Only the classifier flagged visible text, with nothing else to confirm it."
GUARD_FAILED_BLOCK_REASON = "The action guard failed, so this call was blocked as a precaution."
GUARD_FAILED_WARNING = "The action guard failed, so this call was not checked."
L4_SKIPPED_REASON = "The action guard is turned off, so this call was not checked."


class OutboundSignals(Schema):
    """What the action guard observed about one tool call."""

    tool_call: ToolCall
    canary_hit: bool = False
    sensitive_data: bool = False
    high_finding_earlier: bool = False
    egress_count: int = Field(default=0, ge=0)  # including this call
    identical_calls: int = Field(default=0, ge=0)  # including this call
    dlp_hit: bool = False
    misaligned: bool = False
    guard_failed: bool = False


@dataclass(frozen=True)
class _Check:
    """One outbound rule that fired."""

    decision: Decision
    rule_id: str
    reason: str
    severity: Severity


def _is_hidden(finding: Finding) -> bool:
    return finding.segment_origin is not None and finding.segment_origin != "visible"


def _block_message_rule(verdict: Verdict) -> str:
    if not verdict.findings:
        return "layer failure"
    return max(verdict.findings, key=lambda item: (item.severity.rank, item.score)).rule_id


def block_message(verdict: Verdict) -> str:
    """The safe text the agent sees. It names our rule and never repeats the attack."""
    rule = _block_message_rule(verdict)
    return f"Content blocked by PromptShield: possible prompt injection ({rule})"


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def reload(self, policy: Policy) -> None:
        """Swap the policy in one step, so a scan never sees a mix of old and new rules."""
        self._policy = policy

    # Scoring

    def score(self, findings: list[Finding]) -> float:
        """Noisy-OR risk, then the judge's discount if it found the content benign."""
        risk = 1 - prod(1 - self._term(finding) for finding in findings)
        if not any(finding.rule_id == JUDGE_BENIGN_RULE for finding in findings):
            return risk
        thresholds = self._policy.thresholds
        discounted = risk * thresholds.judge_benign_discount
        if any(_is_hidden(finding) for finding in findings):
            # An injected judge must not be able to clear hidden content.
            return max(discounted, min(risk, thresholds.sanitize))
        return discounted

    def should_judge(self, findings: list[Finding]) -> bool:
        """Run L3 only when it could change the outcome. Forced rules already decided."""
        if self._forced_decision(findings) is not None:
            return False
        low, high = self._policy.thresholds.judge_band
        return low <= self.score(findings) <= high

    def _term(self, finding: Finding) -> float:
        weights = self._policy.weights
        term = weights.for_layer(finding.layer) * finding.score
        if finding.layer == "L1" and _is_hidden(finding):
            term *= weights.hidden_origin_boost
        return min(1.0, term)

    # Inbound

    def decide_inbound(
        self, result: PipelineResult, rescan: PipelineResult | None = None
    ) -> Verdict:
        decision, risk = self._raw_inbound(result)
        reasons = self._reasons(result.findings)
        failed = self._failed_layers(result)
        if self._is_capped(result.findings, risk):
            reasons = [CAPPED_REASON, *reasons]

        if failed:
            if self._policy.fail_mode.content_scan == "closed":
                decision = Decision.BLOCK
                reasons = [LAYER_FAILED_BLOCK_REASON, *reasons]
            else:
                reasons = [LAYER_FAILED_WARNING, *reasons]
        elif rescan is not None and self.wants_rescan(result) and self._is_clean(rescan):
            decision = Decision.SANITIZE
            reasons = [DOWNGRADED_REASON, *reasons]

        return self._verdict(
            decision,
            risk,
            result.findings,
            reasons or [NO_ISSUES_REASON],
            result.layers_run,
            result.total_latency_ms,
            result.segments,
        )

    def wants_rescan(self, result: PipelineResult) -> bool:
        """True if a BLOCK might become SANITIZE, so stripping and rescanning is worth doing."""
        decision, _ = self._raw_inbound(result)
        return (
            decision is Decision.BLOCK
            and not self._failed_layers(result)
            and not self._has_visible_injection(result.findings)
            and not any(
                finding.rule_id.startswith(NEVER_DOWNGRADE_PREFIXES) for finding in result.findings
            )
        )

    def _raw_inbound(self, result: PipelineResult) -> tuple[Decision, float]:
        """Forced rules set a minimum. Letting them replace the math would let an attacker add a
        harmless SANITIZE-level link to a page and talk a BLOCK down."""
        thresholds = self._policy.thresholds
        risk = self.score(result.findings)
        decision = self._decision_for(risk)
        cap = self._policy.lone_visible_classifier
        if cap is not None and self._is_capped(result.findings, risk):
            decision = cap
        forced = self._forced_decision(result.findings)
        if forced is None or forced.rank <= decision.rank:
            return decision, risk
        floor = thresholds.block if forced is Decision.BLOCK else thresholds.sanitize
        return forced, max(risk, floor)

    def _is_capped(self, findings: list[Finding], risk: float) -> bool:
        """True when the math says BLOCK but the only strong evidence is L1 on visible text.
        Forced rules still apply after this, so a canary or tag smuggling still blocks."""
        cap = self._policy.lone_visible_classifier
        if cap is None or cap.rank >= self._decision_for(risk).rank:
            return False
        strong = [
            finding
            for finding in findings
            if finding.layer != "L0" and self._term(finding) >= self._policy.thresholds.sanitize
        ]
        return bool(strong) and all(
            finding.layer == "L1" and not _is_hidden(finding) for finding in strong
        )

    def _decision_for(self, risk: float) -> Decision:
        thresholds = self._policy.thresholds
        if risk >= thresholds.block:
            return Decision.BLOCK
        if risk >= thresholds.sanitize:
            return Decision.SANITIZE
        return Decision.ALLOW

    def _forced_decision(self, findings: list[Finding]) -> Decision | None:
        forced = [
            self._policy.force[finding.rule_id]
            for finding in findings
            if finding.rule_id in self._policy.force
        ]
        return max(forced, key=lambda decision: decision.rank, default=None)

    @staticmethod
    def _failed_layers(result: PipelineResult) -> list[str]:
        return [name for name, status in result.layers_run.items() if status == "error"]

    def _has_visible_injection(self, findings: list[Finding]) -> bool:
        """L0 flags are structural, so they don't count. An unknown origin counts as visible."""
        threshold = self._policy.thresholds.sanitize
        return any(
            finding.layer != "L0" and not _is_hidden(finding) and self._term(finding) >= threshold
            for finding in findings
        )

    def _is_clean(self, rescan: PipelineResult) -> bool:
        """A rescan that failed proves nothing, so it can't be clean."""
        return (
            not self._failed_layers(rescan)
            and self._forced_decision(rescan.findings) is None
            and self.score(rescan.findings) < self._policy.thresholds.sanitize
        )

    # Outbound

    def classify_tool(self, tool_call: ToolCall) -> ToolClass:
        """Tools not in the policy use the default class, which is egress out of the box."""
        tool = self._tool_policy(tool_call)
        if tool is None:
            return self._policy.default_tool_class
        if tool.egress_if == "has_query" and self._has_query(tool_call, tool):
            return "egress"
        return tool.tool_class

    def has_sensitive_output(self, tool_call: ToolCall) -> bool:
        """Results of these tools (file contents, emails) are fingerprinted by the taint tracker."""
        tool = self._tool_policy(tool_call)
        return tool is not None and tool.sensitive_output

    def decide_outbound(self, signals: OutboundSignals) -> Verdict:
        started = perf_counter()
        if signals.guard_failed:
            return self._guard_failed_verdict(started)

        checks = self._outbound_checks(signals)
        findings = [self._check_finding(check) for check in checks]
        decision = max(
            (check.decision for check in checks),
            key=lambda item: item.rank,
            default=Decision.ALLOW,
        )
        return self._verdict(
            decision,
            self.score(findings),
            findings,
            [check.reason for check in checks] or [NO_ISSUES_REASON],
            {"L4": "ran"},
            (perf_counter() - started) * 1000,
        )

    def outbound_skipped(self) -> Verdict:
        """L4 turned off (the ablation only): the call goes ahead and the verdict says L4 didn't
        run. Not fail_mode: a disabled layer is `skipped`, not `error`."""
        return self._verdict(Decision.ALLOW, 0.0, [], [L4_SKIPPED_REASON], {"L4": "skipped"}, 0.0)

    def _guard_failed_verdict(self, started: float) -> Verdict:
        closed = self._policy.fail_mode.action_guard == "closed"
        return self._verdict(
            Decision.BLOCK if closed else Decision.ALLOW,
            1.0 if closed else 0.0,
            [],
            [GUARD_FAILED_BLOCK_REASON if closed else GUARD_FAILED_WARNING],
            {"L4": "error"},
            (perf_counter() - started) * 1000,
        )

    def _outbound_checks(self, signals: OutboundSignals) -> list[_Check]:
        checks: list[_Check] = []
        tool = self._tool_policy(signals.tool_call)
        if signals.canary_hit:
            checks.append(
                _Check(
                    Decision.BLOCK,
                    "CANARY.tripped",
                    "A planted canary appeared in an outgoing request: "
                    "this confirms an exfiltration attempt.",
                    Severity.CRITICAL,
                )
            )
        if tool is not None and tool.require_approval:
            checks.append(
                _Check(
                    Decision.REQUIRE_APPROVAL,
                    "L4.TOOL.require_approval",
                    "This tool always needs human approval.",
                    Severity.MEDIUM,
                )
            )
        if self.classify_tool(signals.tool_call) == "egress":
            checks.extend(self._egress_checks(signals, tool))
        if signals.misaligned:
            checks.append(
                _Check(
                    Decision.REQUIRE_APPROVAL,
                    "L4.TASK.misaligned",
                    "This action doesn't appear to match what the user asked for.",
                    Severity.HIGH,
                )
            )
        return checks

    def _egress_checks(self, signals: OutboundSignals, tool: ToolPolicy | None) -> list[_Check]:
        egress = self._policy.egress
        status = self._destination_status(signals.tool_call, tool)
        checks: list[_Check] = []

        def add(
            decision: Decision | OutboundAction, rule: str, reason: str, level: Severity
        ) -> None:
            checks.append(_Check(Decision(decision), f"L4.EGRESS.{rule}", reason, level))

        if status == "denied":
            add(
                Decision.BLOCK,
                "denied_destination",
                "The agent tried to reach a denied destination.",
                Severity.CRITICAL,
            )
        if signals.sensitive_data and status != "allowed":
            add(
                egress.sensitive_data_to_unknown,
                "sensitive_data_to_unknown",
                "The agent tried to send sensitive data to an unknown destination.",
                Severity.CRITICAL,
            )
        if status == "unknown":
            add(
                egress.unknown_destination,
                "unknown_destination",
                "The agent tried to send data to an unknown destination.",
                Severity.HIGH,
            )
        if signals.high_finding_earlier:
            add(
                egress.after_high_finding,
                "after_high_finding",
                "The agent tried to send data after a serious finding in this session.",
                Severity.HIGH,
            )
        if signals.egress_count > egress.max_egress_per_session:
            add(
                Decision.BLOCK,
                "rate_limit",
                "This session reached its limit for outgoing calls.",
                Severity.HIGH,
            )
        if signals.identical_calls > egress.max_identical_calls:
            add(
                Decision.BLOCK,
                "loop_limit",
                "The agent repeated the same outgoing call too many times.",
                Severity.HIGH,
            )
        if signals.dlp_hit and status != "allowed":
            add(
                Decision.BLOCK,
                "dlp",
                "Outgoing data contains a secret or personal data.",
                Severity.CRITICAL,
            )
        return checks

    def _tool_policy(self, tool_call: ToolCall) -> ToolPolicy | None:
        return self._policy.tools.get(f"{tool_call.server}.{tool_call.tool}")

    def _destination_status(self, tool_call: ToolCall, tool: ToolPolicy | None) -> str:
        egress = self._policy.egress
        value = tool_call.args.get(tool.arg_destination) if tool and tool.arg_destination else None
        return classify_destination(
            value, egress.allow_hosts, egress.deny_hosts, egress.allow_recipients
        )

    @staticmethod
    def _has_query(tool_call: ToolCall, tool: ToolPolicy) -> bool:
        value = tool_call.args.get(tool.arg_destination or "")
        return isinstance(value, str) and bool(urlsplit(value).query)

    @staticmethod
    def _check_finding(check: _Check) -> Finding:
        canary = check.rule_id.startswith("CANARY.")
        blocked = check.decision is Decision.BLOCK
        return Finding(
            layer="CANARY" if canary else "L4",
            rule_id=check.rule_id,
            title=check.reason,
            severity=check.severity,
            score=1.0 if blocked else 0.6,
            evidence="",
            latency_ms=0.0,
        )

    # Shared

    @staticmethod
    def _reasons(findings: list[Finding]) -> list[str]:
        """Titles only: evidence can hold attacker text, and reasons may reach the agent."""
        ranked = sorted(findings, key=lambda item: (item.severity.rank, item.score), reverse=True)
        visible = [finding for finding in ranked if finding.rule_id != JUDGE_BENIGN_RULE]
        return list(dict.fromkeys(finding.title for finding in visible))[:MAX_REASONS]

    def _verdict(
        self,
        decision: Decision,
        risk: float,
        findings: list[Finding],
        reasons: list[str],
        layers_run: dict[str, LayerStatus],
        latency_ms: float,
        segments: list[Segment] | None = None,
    ) -> Verdict:
        monitor = self._policy.mode == "monitor"
        return Verdict(
            decision=Decision.ALLOW if monitor else decision,
            would_decision=decision if monitor else None,
            risk_score=risk,
            findings=findings,
            reasons=reasons,
            segments=segments or [],
            layers_run=layers_run,
            total_latency_ms=latency_ms,
        )
