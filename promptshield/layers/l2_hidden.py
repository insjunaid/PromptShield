"""L2: "the AI sees it, the human doesn't" is itself a strong signal.

Hiding alone isn't an attack: menus and cookie banners are hidden all the time. So short hidden text
scores low. Hidden sentences score enough to be stripped even with no known phrase in them, because
the phrase list misses paraphrases and a person can't see what was hidden. Each rule reports once
per scan, because noisy-OR would otherwise turn fifty harmless hidden elements into a block.
"""

import asyncio
import base64
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import NamedTuple, Protocol

import structlog

from promptshield.layers.base import ScanContext
from promptshield.models import ContentItem, Finding, LayerName, Segment, SegmentOrigin, Severity
from promptshield.ocr import UnreadableImage
from promptshield.text.instructions import count_instruction_signals
from promptshield.text.links import exfil_links

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    title: str
    severity: Severity
    score: float


class _CssRules(NamedTuple):
    fragment: _Rule
    sentence: _Rule
    instruction: _Rule


def _css_rules(name: str, title: str) -> _CssRules:
    rule_id = f"L2.CSS.{name}"
    return _CssRules(
        _Rule(rule_id, title, Severity.LOW, 0.1),
        _Rule(rule_id, f"Sentences in {title.lower()}", Severity.MEDIUM, 0.45),
        _Rule(rule_id, f"Instruction in {title.lower()}", Severity.HIGH, 0.85),
    )


CSS_RULES = {
    "display_none": _css_rules("display_none", "Text hidden by CSS"),
    "tiny_font": _css_rules("tiny_font", "Text too small to read"),
    "color_match": _css_rules("color_match", "Text matching its background"),
    "offscreen": _css_rules("offscreen", "Text placed off screen"),
}
SENTENCE_MIN_WORDS = 8
UNSEEN_MARKUP_ORIGINS: frozenset[SegmentOrigin] = frozenset(
    {"html_comment", "meta", "attribute", "hidden_markup"}
)
MARKUP_INSTRUCTION = _Rule(
    "L2.HTML.comment_instruction", "Instruction in page markup", Severity.HIGH, 0.75
)
ZERO_WIDTH_MESSAGE = _Rule(
    "L2.UNICODE.zero_width", "Message hidden in zero-width characters", Severity.HIGH, 0.85
)
ZERO_WIDTH_MARKS = _Rule(
    "L2.UNICODE.zero_width", "Zero-width characters inside words", Severity.MEDIUM, 0.4
)
TAG_MESSAGE = _Rule("L2.UNICODE.tag_smuggling", "Text smuggled in Unicode tags", Severity.HIGH, 0.8)
TAG_INSTRUCTION = _Rule(
    "L2.UNICODE.tag_smuggling", "Instruction smuggled in Unicode tags", Severity.CRITICAL, 0.95
)
BIDI = _Rule("L2.UNICODE.bidi", "Text direction overrides", Severity.MEDIUM, 0.5)
CONFUSABLES = _Rule("L2.UNICODE.confusables", "Words using lookalike letters", Severity.MEDIUM, 0.4)
ENCODED_INSTRUCTION = _Rule(
    "L2.ENCODED.payload", "Encoded text containing an instruction", Severity.HIGH, 0.85
)
EXFIL_LINK = _Rule(
    "L2.MARKDOWN.exfil_link", "Markdown link that can carry data out", Severity.HIGH, 0.7
)
OCR_TEXT = _Rule("L2.IMAGE.ocr_text", "Text read from an image", Severity.INFO, 0.05)
OCR_INSTRUCTION = _Rule("L2.IMAGE.ocr_text", "Instruction written in an image", Severity.HIGH, 0.85)
# An image that can't be read can't be checked, so it should be dropped from the result.
UNREADABLE_IMAGE = _Rule("L2.IMAGE.unread", "Image could not be checked", Severity.MEDIUM, 0.5)
# Missing OCR is a setup choice, not an attack, so it is recorded without raising the risk.
OCR_MISSING = _Rule("L2.IMAGE.unread", "Images not checked: OCR not installed", Severity.INFO, 0.0)
IMPERATIVE_RULE_ID = "L2.INSTR.imperative_to_ai"
IMPERATIVE_BASE_SCORE = 0.3
IMPERATIVE_STEP = 0.15
IMPERATIVE_MAX_SCORE = 0.6

L0_ZERO_WIDTH = "L0.UNICODE.zero_width_present"
L0_BIDI = "L0.UNICODE.bidi_present"
L0_CONFUSABLES = "L0.UNICODE.confusables_present"


def _finding(rule: _Rule, evidence: str, origin: SegmentOrigin | None) -> Finding:
    return Finding(
        layer="L2",
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        score=rule.score,
        evidence=evidence,
        segment_origin=origin,
        latency_ms=0,
    )


def _imperative(signals: int, segment: Segment) -> Finding:
    score = min(IMPERATIVE_BASE_SCORE + IMPERATIVE_STEP * (signals - 1), IMPERATIVE_MAX_SCORE)
    rule = _Rule(IMPERATIVE_RULE_ID, "Text addressed to an AI", Severity.LOW, score)
    return _finding(rule, segment.text, segment.origin)


def _exfil_link(segment: Segment) -> Finding | None:
    for match in exfil_links(segment.text):
        return _finding(EXFIL_LINK, match.group(), segment.origin)
    return None


def _has_sentence(text: str) -> bool:
    """Counted per line, so a long hidden menu of short links isn't a sentence."""
    return any(len(line.split()) >= SENTENCE_MIN_WORDS for line in text.splitlines())


def _css_rule(rules: _CssRules, text: str, instruction: bool) -> _Rule:
    if instruction:
        return rules.instruction
    return rules.sentence if _has_sentence(text) else rules.fragment


def _segment_findings(segment: Segment) -> Iterator[Finding]:
    signals = count_instruction_signals(segment.text)
    instruction = signals > 0
    if segment.hidden_by is not None:
        rule = _css_rule(CSS_RULES[segment.hidden_by], segment.text, instruction)
        yield _finding(rule, segment.text, segment.origin)
    if segment.origin in UNSEEN_MARKUP_ORIGINS and instruction:
        yield _finding(MARKUP_INSTRUCTION, segment.text, segment.origin)
    if segment.origin == "unicode_tag":
        rule = TAG_INSTRUCTION if instruction else TAG_MESSAGE
        yield _finding(rule, segment.text, segment.origin)
    if segment.origin == "zero_width":
        yield _finding(ZERO_WIDTH_MESSAGE, segment.text, segment.origin)
    if segment.origin == "ocr":
        yield _finding(OCR_INSTRUCTION if instruction else OCR_TEXT, segment.text, "ocr")
    if segment.origin == "decoded_payload" and instruction:
        yield _finding(ENCODED_INSTRUCTION, segment.text, segment.origin)
    if instruction:
        yield _imperative(signals, segment)
    link = _exfil_link(segment)
    if link is not None:
        yield link


def _flag_findings(prior: Sequence[Finding]) -> Iterator[Finding]:
    """L0 already decided what is normal use of these characters, so that isn't redone here."""
    for finding in prior:
        if finding.rule_id == L0_ZERO_WIDTH:
            yield _finding(ZERO_WIDTH_MARKS, finding.evidence, "zero_width")
        elif finding.rule_id == L0_BIDI:
            yield _finding(BIDI, finding.evidence, None)
        elif finding.rule_id == L0_CONFUSABLES:
            yield _finding(CONFUSABLES, finding.evidence, None)


def _strongest_per_rule(findings: Iterator[Finding]) -> list[Finding]:
    strongest: dict[str, Finding] = {}
    for finding in findings:
        current = strongest.get(finding.rule_id)
        if current is None or finding.score > current.score:
            strongest[finding.rule_id] = finding
    return list(strongest.values())


def _scan(segments: Sequence[Segment], prior: Sequence[Finding]) -> list[Finding]:
    def all_findings() -> Iterator[Finding]:
        for segment in segments:
            yield from _segment_findings(segment)
        yield from _flag_findings(prior)

    return _strongest_per_rule(all_findings())


class ImageReader(Protocol):
    async def read(self, image: bytes) -> str: ...


class HiddenContentLayer:
    name: LayerName = "L2"

    def __init__(self, ocr: ImageReader | None = None, max_images: int = 8) -> None:
        """With no reader, images go unchecked and that is recorded, but the other rules still
        run: one missing optional tool shouldn't switch off the whole layer."""
        self._ocr = ocr
        self._max_images = max_images

    async def warmup(self) -> None:
        """OCR loads on the first image, because most scans have none."""

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        """Reads images first, so their text goes through the same rules and on to L1. An OCR
        failure is raised: an image that was meant to be checked and wasn't must fail closed."""
        images = [item for item in ctx.items if item.kind == "image"]
        unread = await self._read_images(images, ctx.segments)
        found = await asyncio.to_thread(_scan, list(ctx.segments), list(ctx.prior_findings))
        return [*found, *unread]

    async def _read_images(
        self, images: list[ContentItem], segments: list[Segment]
    ) -> list[Finding]:
        if not images:
            return []
        if self._ocr is None:
            logger.warning("ocr_unavailable", images=len(images))
            return [_finding(OCR_MISSING, f"{len(images)} images not checked", None)]
        problems: list[str] = []
        if len(images) > self._max_images:
            problems.append(f"{len(images) - self._max_images} images over the limit")
        for item in images[: self._max_images]:
            try:
                text = await self._ocr.read(base64.b64decode(item.data))
            except UnreadableImage as error:
                problems.append(str(error))
                continue
            if text.strip():
                segments.append(Segment(text=text, origin="ocr"))
        if not problems:
            return []
        return [_finding(UNREADABLE_IMAGE, "; ".join(problems), None)]
