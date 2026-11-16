"""L0: turns raw tool output into tagged text segments for the other layers.

Findings here are only structural flags, with a low policy weight. L2 owns the judgement about
whether a trick is an attack.
"""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field

from promptshield.config import Settings
from promptshield.layers.base import ScanContext
from promptshield.models import (
    ContentItem,
    Finding,
    LayerName,
    Segment,
    SegmentOrigin,
    Severity,
)
from promptshield.text.css import CssLimits, HiddenBy
from promptshield.text.decoders import PayloadFinder
from promptshield.text.extract import item_parts
from promptshield.text.unicode_hygiene import CleanText, clean_text

ZERO_WIDTH_ENCODING = "zero_width_binary"


@dataclass
class _Extraction:
    """What one scan has found so far."""

    segments: list[Segment] = field(default_factory=list)
    seen: set[tuple[str, str, str | None]] = field(default_factory=set)
    tag_messages: list[str] = field(default_factory=list)
    zero_width_count: int = 0
    bidi_count: int = 0
    confusable_words: list[str] = field(default_factory=list)
    payloads: int = 0
    payload_limit_hit: bool = False
    css_limit_hit: bool = False

    def add(self, segment: Segment) -> None:
        key = (segment.origin, segment.text, segment.hidden_by)
        if segment.text.strip() and key not in self.seen:
            self.seen.add(key)
            self.segments.append(segment)

    def absorb(self, clean: CleanText) -> None:
        if clean.tag_message:
            self.tag_messages.append(clean.tag_message)
        self.zero_width_count += clean.zero_width_count
        self.bidi_count += clean.bidi_count
        self.confusable_words.extend(clean.confusable_words)

    def findings(self) -> list[Finding]:
        candidates = [
            self._tag_finding(),
            self._zero_width_finding(),
            self._bidi_finding(),
            self._confusables_finding(),
            self._limit_finding(),
            self._css_limit_finding(),
        ]
        return [finding for finding in candidates if finding is not None]

    def _tag_finding(self) -> Finding | None:
        if not self.tag_messages:
            return None
        return _flag(
            "L0.UNICODE.tag_chars_present",
            "Invisible Unicode tag characters",
            Severity.HIGH,
            0.8,
            " ".join(self.tag_messages),
            "unicode_tag",
        )

    def _zero_width_finding(self) -> Finding | None:
        if not self.zero_width_count:
            return None
        return _flag(
            "L0.UNICODE.zero_width_present",
            "Zero-width characters outside normal use",
            Severity.LOW,
            0.3,
            f"{self.zero_width_count} zero-width characters removed",
            "zero_width",
        )

    def _bidi_finding(self) -> Finding | None:
        if not self.bidi_count:
            return None
        return _flag(
            "L0.UNICODE.bidi_present",
            "Text direction controls outside right-to-left text",
            Severity.MEDIUM,
            0.4,
            f"{self.bidi_count} direction controls removed",
            None,
        )

    def _confusables_finding(self) -> Finding | None:
        if not self.confusable_words:
            return None
        return _flag(
            "L0.UNICODE.confusables_present",
            "Words mixing Latin with lookalike letters",
            Severity.LOW,
            0.3,
            " ".join(self.confusable_words),
            None,
        )

    def _limit_finding(self) -> Finding | None:
        if not self.payload_limit_hit:
            return None
        return _flag(
            "L0.ENCODED.limit_reached",
            "Too many encoded blobs to decode them all",
            Severity.LOW,
            0.3,
            f"stopped after {self.payloads} decoded blobs",
            None,
        )

    def _css_limit_finding(self) -> Finding | None:
        if not self.css_limit_hit:
            return None
        return _flag(
            "L0.CSS.limit_reached",
            "Too many style rules to check them all",
            Severity.LOW,
            0.3,
            "some style rules were not checked",
            None,
        )


def _flag(
    rule_id: str,
    title: str,
    severity: Severity,
    score: float,
    evidence: str,
    origin: SegmentOrigin | None,
) -> Finding:
    return Finding(
        layer="L0",
        rule_id=rule_id,
        title=title,
        severity=severity,
        score=score,
        evidence=evidence,
        segment_origin=origin,
        latency_ms=0,
    )


class NormalizeLayer:
    name: LayerName = "L0"

    def __init__(self, settings: Settings) -> None:
        self._finder = PayloadFinder(settings.decode_min_length, settings.decode_printable_ratio)
        self._max_depth = settings.decode_max_depth
        self._max_payloads = settings.decode_max_payloads
        self._css_limits = CssLimits(
            max_selector_checks=settings.css_max_selector_checks,
            min_contrast=settings.css_min_contrast,
            tiny_font_px=settings.css_tiny_font_px,
            offscreen_px=settings.css_offscreen_px,
        )

    async def warmup(self) -> None:
        """Nothing to load."""

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        """Runs in a thread: a large page takes real CPU time, and the event loop must stay free."""
        extraction = await asyncio.to_thread(self._extract, ctx.items)
        ctx.segments.extend(extraction.segments)
        return extraction.findings()

    def _extract(self, items: Sequence[ContentItem]) -> _Extraction:
        extraction = _Extraction()
        for item in items:
            content = item_parts(item, self._css_limits)
            extraction.css_limit_hit |= content.css_limit_hit
            for part in content.parts:
                self._process(part.text, part.origin, extraction, hidden_by=part.hidden_by)
        return extraction

    def _process(
        self,
        text: str,
        origin: SegmentOrigin,
        extraction: _Extraction,
        *,
        encoding: str | None = None,
        offset: int | None = None,
        hidden_by: HiddenBy | None = None,
        depth: int = 0,
    ) -> None:
        """Depth counts layers of encoding, so base64 inside base64 is read, up to a limit."""
        clean = clean_text(text)
        extraction.absorb(clean)
        extraction.add(
            Segment(
                text=clean.text,
                origin=origin,
                encoding=encoding,
                offset=offset,
                original=None if clean.text == text else text,
                hidden_by=hidden_by,
            )
        )
        if depth >= self._max_depth:
            return
        if clean.tag_message:
            self._process(clean.tag_message, "unicode_tag", extraction, depth=depth + 1)
        if clean.zero_width_message:
            self._process(
                clean.zero_width_message,
                "zero_width",
                extraction,
                encoding=ZERO_WIDTH_ENCODING,
                depth=depth + 1,
            )
        self._decode_payloads(clean.text, extraction, depth)

    def _decode_payloads(self, text: str, extraction: _Extraction, depth: int) -> None:
        for payload in self._finder.find(text):
            if extraction.payloads >= self._max_payloads:
                extraction.payload_limit_hit = True
                return
            extraction.payloads += 1
            self._process(
                payload.text,
                "decoded_payload",
                extraction,
                encoding=payload.encoding,
                offset=payload.offset,
                depth=depth + 1,
            )
