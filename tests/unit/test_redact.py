"""Secrets must never reach storage, logs or the dashboard in clear."""

import base64

import pytest
from hypothesis import given
from hypothesis import strategies as st

from promptshield.models import ContentItem, Decision, Event, Finding, Segment, Severity, Verdict
from promptshield.redact import BINARY_PLACEHOLDER, TRUNCATION_MARK, Redactor

CANARY = "sk-canary-a1b2c3d4e5f6"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"key={CANARY}", "key=sk-canary-…e5f6"),
        ("sk-abcdefghijklmnop1234", "sk-…1234"),
        ("hf_" + "a" * 30 + "wxyz", "hf_…wxyz"),
        ("ghp_" + "b" * 30 + "wxyz", "ghp_…wxyz"),
        ("AKIAIOSFODNN7EXAMPLE", "AKIA…MPLE"),
        ("Bearer abcdefghijklmnopqrstuvwx", "Bearer …uvwx"),
    ],
)
def test_known_secret_shapes_are_masked(text: str, expected: str) -> None:
    assert Redactor().scrub_text(text) == expected


def test_jwt_is_masked() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P"
    masked = Redactor().scrub_text(token)
    assert "dozjgNry" not in masked
    assert masked.startswith("eyJ…")


def test_private_key_block_is_removed() -> None:
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----"
    assert "abc123" not in Redactor().scrub_text(f"before {key} after")


def test_private_key_without_an_end_marker_is_removed() -> None:
    assert "abc123" not in Redactor().scrub_text("-----BEGIN RSA PRIVATE KEY-----\nabc123")


def test_ordinary_text_is_unchanged() -> None:
    text = "Task risk-assessment and the sk- prefix are fine. Bearer of bad news."
    assert Redactor().scrub_text(text) == text


def test_registered_literal_is_masked() -> None:
    redactor = Redactor()
    redactor.add_secret("correct-horse-battery")
    assert "horse" not in redactor.scrub_text("password: correct-horse-battery")


def test_empty_literal_is_ignored() -> None:
    redactor = Redactor()
    redactor.add_secret("")
    assert redactor.scrub_text("hello") == "hello"


def test_long_text_is_truncated_to_the_limit() -> None:
    result = Redactor(text_limit=100).scrub_text("x" * 500)
    assert len(result) == 100
    assert result.endswith(TRUNCATION_MARK)


def test_a_secret_on_the_truncation_edge_does_not_leak() -> None:
    text = "x" * 80 + CANARY + "y" * 100
    assert "a1b2c3d4" not in Redactor(text_limit=100).scrub_text(text)


def test_nested_values_and_keys_are_scrubbed() -> None:
    value = {"args": [{"body": CANARY}], CANARY: 1, "count": 3}
    scrubbed = Redactor().scrub_value(value)
    assert CANARY not in str(scrubbed)
    assert scrubbed["count"] == 3


def test_every_part_of_an_event_is_scrubbed() -> None:
    verdict = Verdict(
        decision=Decision.BLOCK,
        risk_score=1,
        findings=[
            Finding(
                layer="CANARY",
                rule_id="CANARY.tripped",
                title="Canary",
                severity=Severity.CRITICAL,
                score=1,
                evidence=CANARY,
                latency_ms=1,
            )
        ],
        reasons=[f"Agent tried to send {CANARY}"],
        segments=[Segment(text=CANARY, origin="visible")],
        sanitized_items=[ContentItem(kind="text", data=CANARY, source="web")],
    )
    event = Event(type="verdict", verdict=verdict, payload={"args": {"data": CANARY}})
    assert "a1b2c3d4" not in Redactor().scrub_model(event).model_dump_json()


def test_binary_content_is_replaced_and_stays_valid() -> None:
    encoded = base64.b64encode(b"\x89PNG" * 2000).decode()
    item = ContentItem(kind="image", data=encoded, data_is_base64=True, source="web")
    verdict = Verdict(decision=Decision.SANITIZE, risk_score=0.5, sanitized_items=[item])
    scrubbed = Redactor(text_limit=100).scrub_model(Event(type="verdict", verdict=verdict))
    assert scrubbed.verdict is not None
    assert scrubbed.verdict.sanitized_items is not None
    assert scrubbed.verdict.sanitized_items[0].data == BINARY_PLACEHOLDER


def test_scrubbing_keeps_a_clean_event_equal() -> None:
    event = Event(type="session_start", session_id="s1", payload={"url": "http://localhost:8081"})
    assert Redactor().scrub_model(event) == event


@given(st.text())
def test_scrubbing_never_fails_and_is_stable(text: str) -> None:
    redactor = Redactor(text_limit=200)
    once = redactor.scrub_text(text)
    assert redactor.scrub_text(once) == once


@given(st.text(max_size=50), st.text(max_size=50))
def test_a_canary_inside_any_text_is_masked(before: str, after: str) -> None:
    assert "a1b2c3d4" not in Redactor().scrub_text(f"{before} {CANARY} {after}")
