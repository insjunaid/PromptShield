"""Canary tokens: planted fake secrets. One leaving the system proves the agent was compromised.

This matcher is written separately from the lab judge's on purpose. The judge decides whether an
attack succeeded; if both shared a bug, the shield would miss a leak and the measurement would miss
it too, which would hide the failure instead of showing it.
"""

import base64
import binascii
import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import quote, unquote

from promptshield.layers.base import ScanContext
from promptshield.models import Finding, LayerName, Severity
from promptshield.redact import Redactor
from promptshield.taint import strings_in

TRIPPED_RULE = "CANARY.tripped"
SEEN_INBOUND_RULE = "CANARY.seen_inbound"
NOT_ALPHANUMERIC = re.compile(r"[^a-z0-9]")
ENCODED_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
# Shorter values would match ordinary text once separators are dropped.
MIN_CANARY_CHARS = 8
DECODE_DEPTH = 2


def _squeeze(text: str) -> str:
    """Lowercase and drop separators, so `S K - c a n a r y` still matches."""
    return NOT_ALPHANUMERIC.sub("", text.lower())


def _decoded(blob: str) -> Iterator[str]:
    padded = blob + "=" * (-len(blob) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            yield decode(padded).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
    try:
        yield bytes.fromhex(blob).decode("utf-8", errors="ignore")
    except ValueError:
        return


def _views(text: str) -> Iterator[str]:
    """Every form an agent might send: as is, reversed, URL-decoded, and decoded from base64 or hex,
    nested up to two layers. Not capped by count: a cap would let padding hide the secret. Decoding
    shrinks the text, so the total work stays a small multiple of the input."""
    frontier = [text]
    for _ in range(DECODE_DEPTH + 1):
        next_frontier: list[str] = []
        for view in frontier:
            for form in (view, unquote(view)):
                yield form
                yield form[::-1]
                next_frontier.extend(
                    decoded for blob in ENCODED_BLOB.findall(form) for decoded in _decoded(blob)
                )
        frontier = next_frontier


def variants(value: str) -> list[str]:
    """Spellings to redact before anything is stored or shown, so an encoded leak in the event log
    doesn't reveal the canary."""
    raw = value.encode("utf-8")
    standard = base64.b64encode(raw).decode()
    url_safe = base64.urlsafe_b64encode(raw).decode()
    forms = {
        value,
        value.lower(),
        value.upper(),
        value[::-1],
        standard,
        standard.rstrip("="),
        url_safe,
        url_safe.rstrip("="),
        raw.hex(),
        quote(value, safe=""),
    }
    return sorted(forms)


class CanaryStore:
    def __init__(self, redactor: Redactor | None = None) -> None:
        self._redactor = redactor
        self._squeezed: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._squeezed)

    def add(self, values: Iterable[str]) -> None:
        for value in values:
            squeezed = _squeeze(value)
            if len(squeezed) < MIN_CANARY_CHARS:
                raise ValueError("a canary must have at least 8 letters or digits")
            self._squeezed[squeezed] = value
            if self._redactor is not None:
                for variant in variants(value):
                    self._redactor.add_secret(variant)

    def found_in(self, text: str) -> bool:
        if not self._squeezed:
            return False
        return any(canary in _squeeze(view) for view in _views(text) for canary in self._squeezed)

    def in_arguments(self, args: Any) -> bool:
        """True if any string in the tool arguments, keys included, carries a canary."""
        return any(self.found_in(text) for text in strings_in(args))


class CanaryLayer:
    """Inbound: a canary in a tool result is logged, not blocked. Reading the decoy secrets file is
    normal; sending a canary out is what trips (`CANARY.tripped`, checked by the action guard)."""

    name: LayerName = "CANARY"

    def __init__(self, store: CanaryStore) -> None:
        self._store = store

    async def warmup(self) -> None:
        """Nothing to load."""

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        hits = [segment for segment in ctx.segments if self._store.found_in(segment.text)]
        if not hits:
            return []
        return [
            Finding(
                layer="CANARY",
                rule_id=SEEN_INBOUND_RULE,
                title="A planted canary appeared in tool output",
                severity=Severity.INFO,
                score=0.0,
                evidence=f"{len(hits)} segments",
                segment_origin=hits[0].origin,
                latency_ms=0,
            )
        ]
