"""Schemas are the trust boundary for attacker-controlled tool output."""

import base64
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from promptshield.models import (
    MAX_EVIDENCE_CHARS,
    Approval,
    ContentItem,
    Decision,
    Direction,
    Event,
    Finding,
    Segment,
    SessionInfo,
    Severity,
    StatsSnapshot,
    ToolCall,
    Verdict,
    new_id,
)


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "layer": "L2",
        "rule_id": "L2.CSS.color_match",
        "title": "Hidden text",
        "severity": Severity.HIGH,
        "score": 0.9,
        "evidence": "white text",
        "latency_ms": 1.5,
    }
    return Finding.model_validate(values | overrides)


def make_tool_call() -> ToolCall:
    return ToolCall(session_id="s1", tool="send_email", server="mail", args={"to": "a@b.example"})


def test_severity_ranks_by_danger_not_alphabet() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_decision_ranks_most_severe_last() -> None:
    ranked = sorted(Decision, key=lambda decision: decision.rank)
    assert ranked == [
        Decision.ALLOW,
        Decision.SANITIZE,
        Decision.REQUIRE_APPROVAL,
        Decision.BLOCK,
    ]


def test_decision_values_match_policy_yaml() -> None:
    assert Decision("REQUIRE_APPROVAL") is Decision.REQUIRE_APPROVAL


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Segment.model_validate({"text": "x", "origin": "visible", "surprise": 1})


def test_unknown_segment_origin_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Segment.model_validate({"text": "x", "origin": "decoded_base64"})


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_finding_score_must_stay_in_range(score: float) -> None:
    with pytest.raises(ValidationError):
        make_finding(score=score)


def test_long_evidence_is_truncated() -> None:
    finding = make_finding(evidence="x" * 5000)
    assert len(finding.evidence) == MAX_EVIDENCE_CHARS
    assert finding.evidence.endswith("…")


def test_evidence_at_the_limit_is_unchanged() -> None:
    evidence = "x" * MAX_EVIDENCE_CHARS
    assert make_finding(evidence=evidence).evidence == evidence


@pytest.mark.parametrize("risk", [-0.1, 1.2])
def test_verdict_risk_must_stay_in_range(risk: float) -> None:
    with pytest.raises(ValidationError):
        Verdict(decision=Decision.ALLOW, risk_score=risk)


def test_image_must_be_base64() -> None:
    with pytest.raises(ValidationError, match="base64"):
        ContentItem(kind="image", data="not flagged", source="web")


def test_invalid_base64_is_rejected() -> None:
    with pytest.raises(ValidationError, match="base64"):
        ContentItem(kind="image", data="@@not base64@@", data_is_base64=True, source="web")


def test_raw_bytes_returns_the_original_binary() -> None:
    original = bytes(range(256))
    item = ContentItem(
        kind="image",
        data=base64.b64encode(original).decode(),
        data_is_base64=True,
        source="web",
    )
    assert item.raw_bytes() == original


def test_raw_bytes_encodes_plain_text() -> None:
    item = ContentItem(kind="text", data="नमस्ते", source="web")
    assert item.raw_bytes().decode("utf-8") == "नमस्ते"


def test_approval_must_expire_after_creation() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="expires"):
        Approval(
            session_id="s1",
            tool_call=make_tool_call(),
            reasons=["unknown destination"],
            created=now,
            expires=now - timedelta(seconds=1),
        )


def test_approval_starts_pending() -> None:
    approval = Approval(
        session_id="s1",
        tool_call=make_tool_call(),
        reasons=[],
        expires=datetime.now(UTC) + timedelta(minutes=2),
    )
    assert approval.status == "pending"


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Event.model_validate({"type": "session_start", "ts": "2026-11-05T10:00:00"})


def test_unknown_event_type_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Event.model_validate({"type": "not_an_event"})


def test_session_defaults_allow_clients_that_send_no_task() -> None:
    session = SessionInfo()
    assert session.user_task is None
    assert session.shield is True


def test_registry_events_need_no_session() -> None:
    assert Event(type="registry_alert").session_id is None


def test_ids_sort_by_creation_time() -> None:
    first, second = new_id(), new_id()
    assert len(first) == 26
    assert first[:8] <= second[:8]


def test_defaults_are_not_shared_between_instances() -> None:
    first = Verdict(decision=Decision.ALLOW, risk_score=0)
    second = Verdict(decision=Decision.ALLOW, risk_score=0)
    first.findings.append(make_finding())
    assert second.findings == []


def test_event_survives_a_json_round_trip() -> None:
    verdict = Verdict(
        decision=Decision.ALLOW,
        would_decision=Decision.BLOCK,
        risk_score=0.8,
        findings=[make_finding(segment_origin="hidden_css")],
        reasons=["Hidden text found"],
        sanitized_items=[ContentItem(kind="text", data="clean", source="web")],
        segments=[Segment(text="payload", origin="decoded_payload", encoding="base64")],
        layers_run={"L1": "ran", "L2": "skipped"},
        total_latency_ms=12.5,
    )
    event = Event(
        session_id="s1",
        type="verdict",
        direction=Direction.INBOUND,
        tool="web_fetch",
        verdict=verdict,
        payload={"url": "http://localhost:8081/a02.html"},
    )
    assert Event.model_validate_json(event.model_dump_json()) == event


def test_timestamps_serialize_as_utc() -> None:
    event = Event(type="session_start", ts=datetime(2026, 11, 5, 10, 0, tzinfo=UTC))
    assert '"ts":"2026-11-05T10:00:00Z"' in event.model_dump_json()


def test_stats_snapshot_starts_empty() -> None:
    assert StatsSnapshot().model_dump()["scans"] == 0
