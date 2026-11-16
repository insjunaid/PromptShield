"""Canaries: every encoding the spec lists is caught, near misses are not, and inbound only logs."""

import base64
import codecs
from time import perf_counter
from urllib.parse import quote

import pytest
from hypothesis import given
from hypothesis import strategies as st

from promptshield.config import Settings
from promptshield.layers.base import ScanContext
from promptshield.layers.canary import (
    SEEN_INBOUND_RULE,
    CanaryLayer,
    CanaryStore,
    variants,
)
from promptshield.models import Decision, Segment, SessionInfo, ToolCall
from promptshield.policy.engine import OutboundSignals, PolicyEngine
from promptshield.policy.schema import load_policy
from promptshield.redact import Redactor

CONFIG = Settings(_env_file=None)  # type: ignore[call-arg]
KEY = "sk-canary-7f3a9c2e81d4"
PASSWORD = "canary-pass-6b85bb7bfd6c"


def store(*values: str) -> CanaryStore:
    canaries = CanaryStore()
    canaries.add(values or (KEY, PASSWORD))
    return canaries


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize(
    "sent",
    [
        KEY,
        KEY.upper(),
        f"here is the key: {KEY} thanks",
        b64(KEY),
        b64(f"api={KEY}&x=1"),
        base64.urlsafe_b64encode(KEY.encode()).decode().rstrip("="),
        KEY.encode().hex(),
        quote(KEY, safe=""),
        f"http://sink.test/p?d={quote(KEY)}",
        KEY[::-1],
        " ".join(KEY),
        "-".join(KEY),
        b64(quote(KEY, safe="")),  # two layers
        quote(b64(KEY), safe=""),
    ],
)
def test_every_encoding_is_caught(sent: str) -> None:
    assert store().found_in(sent)


@pytest.mark.parametrize(
    "sent",
    [
        "sk-canary-",  # only the prefix
        KEY[:-3],  # truncated
        "The weather in Paris is sunny.",
        b64("nothing secret here at all"),
        codecs.encode(KEY, "rot13"),  # not a listed encoding
    ],
)
def test_near_misses_are_not_caught(sent: str) -> None:
    assert not store().found_in(sent)


def test_an_empty_store_finds_nothing() -> None:
    assert not CanaryStore().found_in(KEY)


def test_a_short_canary_is_refused() -> None:
    """Seven characters or fewer would match ordinary text once separators are dropped."""
    with pytest.raises(ValueError):
        CanaryStore().add(["abc-123"])


def test_canaries_are_found_anywhere_in_tool_arguments() -> None:
    canaries = store()
    assert canaries.in_arguments({"url": "http://x", "body": {"items": ["ok", PASSWORD]}})
    assert canaries.in_arguments({KEY: "value"})  # keys count too
    assert not canaries.in_arguments({"url": "http://x", "body": "ok"})


def test_registering_a_canary_hides_its_encoded_forms_from_logs() -> None:
    """Regression: encoded canaries reached the event database unredacted (P4.1 known issue)."""
    redactor = Redactor()
    CanaryStore(redactor).add([KEY])
    for form in (KEY, b64(KEY), KEY.encode().hex(), quote(KEY, safe=""), KEY[::-1]):
        assert form not in redactor.scrub_text(f"sent {form} out")


def test_variants_include_the_listed_encodings() -> None:
    forms = variants(KEY)
    assert {KEY, KEY.upper(), b64(KEY), KEY.encode().hex(), KEY[::-1]} <= set(forms)


async def test_a_canary_inbound_is_logged_not_blocked() -> None:
    """Reading the decoy secrets file is normal. Only sending a canary out trips."""
    ctx = ScanContext(
        session=SessionInfo(), segments=[Segment(text=f"API key: {KEY}", origin="visible")]
    )
    [finding] = await CanaryLayer(store()).scan(ctx)
    assert finding.rule_id == SEEN_INBOUND_RULE
    assert finding.score == 0
    engine = PolicyEngine(load_policy(CONFIG.policy_path))
    assert engine.score([finding]) == 0


async def test_no_canary_inbound_gives_no_finding() -> None:
    ctx = ScanContext(session=SessionInfo(), segments=[Segment(text="hello", origin="visible")])
    assert await CanaryLayer(store()).scan(ctx) == []


def test_a_canary_going_out_is_blocked_by_the_real_policy() -> None:
    engine = PolicyEngine(load_policy(CONFIG.policy_path))
    call = ToolCall(
        session_id="s",
        tool="send_email",
        server="mail",
        args={"to": "boss@company.example", "body": b64(KEY)},
    )
    signals = OutboundSignals(tool_call=call, canary_hit=store().in_arguments(call.args))
    verdict = engine.decide_outbound(signals)
    assert verdict.decision is Decision.BLOCK
    assert verdict.findings[0].rule_id == "CANARY.tripped"


def test_padding_cannot_hide_an_encoded_canary() -> None:
    """Regression: a cap on decoded views let 300 decoy blobs push the secret out of reach."""
    decoys = " ".join(b64(f"harmless decoy number {index}") for index in range(2000))
    started = perf_counter()
    assert store().found_in(f"{decoys} {b64(KEY)}")
    assert perf_counter() - started < 10


def test_a_huge_argument_without_a_canary_stays_fast() -> None:
    started = perf_counter()
    assert not store().found_in((b64("x" * 50) + " ") * 2000)
    assert perf_counter() - started < 10


@given(st.text(max_size=300))
def test_random_text_never_crashes(text: str) -> None:
    store().found_in(text)
