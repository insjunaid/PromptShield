"""Splits structured content into text parts, tagged with where a reader would (not) see them."""

import base64
import json
import re
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, NamedTuple

import structlog
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from bs4.element import Doctype, PreformattedString, Tag

from promptshield.models import ContentItem, SegmentOrigin
from promptshield.text.css import CssLimits, HiddenBy, HiddenElement, find_hidden

logger = structlog.get_logger(__name__)

HTML_MIME = "text/html"

HTML_HINT = re.compile(
    r"<(?:!--|(?:!doctype|html|head|body|div|span|p|a|img|table|meta|style|script|noscript"
    r"|template|input)[\s>/])",
    re.IGNORECASE,
)
READABLE_ATTRIBUTES = ("alt", "title", "aria-label", "aria-description", "placeholder")
DATA_ATTRIBUTE_PREFIX = "data-"
UNRENDERED_TAGS = ("noscript", "template")
JAVASCRIPT_TYPES = frozenset(
    {"", "module", "text/javascript", "application/javascript", "application/ecmascript"}
)
BLOCK_TAGS = frozenset(
    "address article aside blockquote br dd details div dl dt fieldset figcaption figure footer "
    "form h1 h2 h3 h4 h5 h6 header hr li main nav ol p pre section summary table td th tr ul title"
    "".split()
)
SPACES = re.compile(r"[ \t]+")
BLANK_LINES = re.compile(r"\s*\n\s*")


class TextPart(NamedTuple):
    text: str
    origin: SegmentOrigin
    hidden_by: HiddenBy | None = None


@dataclass(frozen=True)
class HtmlContent:
    parts: list[TextPart] = field(default_factory=list)
    css_limit_hit: bool = False


def looks_like_html(text: str) -> bool:
    """Tools such as web fetchers return HTML as plain text, so the kind alone can't be trusted."""
    return HTML_HINT.search(text) is not None


def looks_like_json(text: str) -> bool:
    return text.lstrip()[:1] in ("{", "[")


def flatten_json(text: str) -> str | None:
    """All strings in the document, keys included, since an attacker controls both. None if the
    text isn't JSON. The walk is iterative, because nesting depth is the sender's choice."""
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return None
    found: list[str] = []
    stack: list[Any] = [document]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, dict):
            for key, item in reversed(value.items()):
                stack.extend((item, key))
        elif isinstance(value, list):
            stack.extend(reversed(value))
    return "\n".join(found)


def extract_html(html: str, limits: CssLimits | None = None) -> HtmlContent:
    """Visible text first, then everything an AI reads but a person doesn't. If parsing fails, the
    whole input comes back as one part, so unparsable markup still gets scanned."""
    try:
        return _extract(html, limits or CssLimits())
    except Exception as error:
        logger.warning("html_parse_failed", error=type(error).__name__)
        return HtmlContent([TextPart(html, "visible")])


def _extract(html: str, limits: CssLimits) -> HtmlContent:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
        warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
        soup = BeautifulSoup(html, "lxml")
    stylesheet = "\n".join(tag.get_text() for tag in soup.find_all("style"))
    unseen = [*_take_comments(soup), *_read_attributes(soup), *_take_unrendered(soup)]
    scan = find_hidden(soup, stylesheet, limits)
    hidden = _take_hidden(scan.elements)
    parts = [part for part in (_visible_part(soup), *hidden, *unseen) if part.text.strip()]
    return HtmlContent(parts, scan.limit_hit)


def _take_comments(soup: BeautifulSoup) -> list[TextPart]:
    """Comments, CDATA, declarations and processing instructions share a base class in bs4."""
    nodes = [
        node
        for node in soup.find_all(string=True)
        if isinstance(node, PreformattedString) and not isinstance(node, Doctype)
    ]
    parts = [TextPart(str(node), "html_comment") for node in nodes]
    for node in nodes:
        node.extract()
    return parts


def _read_attributes(soup: BeautifulSoup) -> list[TextPart]:
    parts: list[TextPart] = []
    for tag in soup.find_all(True):
        if tag.name == "meta" and tag.get("content"):
            parts.append(TextPart(str(tag["content"]), "meta"))
        parts.extend(TextPart(str(tag[name]), "attribute") for name in _attribute_names(tag))
    return parts


def _attribute_names(tag: Tag) -> list[str]:
    names = [
        name
        for name in tag.attrs
        if name in READABLE_ATTRIBUTES or name.startswith(DATA_ATTRIBUTE_PREFIX)
    ]
    if tag.name == "input" and str(tag.get("type", "")).lower() == "hidden" and tag.get("value"):
        names.append("value")
    return names


def _take_unrendered(soup: BeautifulSoup) -> list[TextPart]:
    """Executable scripts and styles are dropped unread: they are large and rarely prose. That
    leaves a gap, listed in PROGRESS.md. Data blocks such as JSON-LD are kept."""
    parts: list[TextPart] = []
    for tag in soup.find_all([*UNRENDERED_TAGS, "script", "style"]):
        if tag.decomposed:
            continue
        if tag.name in UNRENDERED_TAGS or _is_data_script(tag):
            parts.append(TextPart(tag.get_text(" ", strip=True), "hidden_markup"))
        tag.decompose()
    return parts


def _take_hidden(elements: list[HiddenElement]) -> list[TextPart]:
    """One part per way of hiding, so each rule sees its own text."""
    grouped: dict[HiddenBy, list[str]] = defaultdict(list)
    for element in elements:
        grouped[element.hidden_by].append(_text_of(element.tag))
        element.tag.extract()
    return [
        TextPart("\n".join(texts), "hidden_css", hidden_by) for hidden_by, texts in grouped.items()
    ]


def _is_data_script(tag: Tag) -> bool:
    return tag.name == "script" and str(tag.get("type", "")).lower() not in JAVASCRIPT_TYPES


def _visible_part(soup: BeautifulSoup) -> TextPart:
    return TextPart(_text_of(soup), "visible")


def _text_of(root: Tag) -> str:
    """Text is joined with nothing between inline tags, so `<b>ig</b><b>nore</b>` stays one word
    for the classifier. Block tags start a new line, so paragraphs don't run together.

    One pass over the tree on purpose: adding nodes to it costs time per level of nesting, which
    let a deeply nested page take seconds.
    """
    pieces: list[str] = []
    for node in root.descendants:
        if isinstance(node, Tag):
            if node.name in BLOCK_TAGS:
                pieces.append("\n")
        elif not isinstance(node, PreformattedString):
            pieces.append(str(node))
    text = SPACES.sub(" ", "".join(pieces))
    return BLANK_LINES.sub("\n", text).strip()


def scrub(text: str) -> str:
    """JSON escapes can produce lone surrogates, which can't be encoded or stored."""
    return text.encode("utf-8", "replace").decode("utf-8")


def item_text(item: ContentItem) -> str:
    if item.data_is_base64:
        return base64.b64decode(item.data).decode("utf-8", "replace")
    return scrub(item.data)


def item_parts(item: ContentItem, limits: CssLimits) -> HtmlContent:
    """Images are left to OCR in L2. The declared kind is a hint, because tools often return HTML
    or JSON as plain text."""
    if item.kind == "image":
        return HtmlContent()
    text = item_text(item)
    if item.kind == "json" or looks_like_json(text):
        flat = flatten_json(text)
        text = text if flat is None else scrub(flat)
    if item.kind == "html" or item.mime == HTML_MIME or looks_like_html(text):
        return extract_html(text, limits)
    return HtmlContent([TextPart(text, "visible")])
