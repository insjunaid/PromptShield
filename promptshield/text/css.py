"""Works out which elements a person can't see, from inline styles and `<style>` rules.

The cascade is followed properly (specificity, `!important`, inheritance), because a shortcut here
is a bypass: `#x{display:none} div{display:block}` is hidden, whatever the source order suggests.
External stylesheets aren't fetched, so a page that links one has an unknown background.
"""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Literal

import structlog
from bs4 import BeautifulSoup
from bs4.element import NavigableString, PreformattedString, Tag
from PIL import ImageColor

logger = structlog.get_logger(__name__)

HiddenBy = Literal["display_none", "tiny_font", "color_match", "offscreen"]
Rgb = tuple[int, int, int]
Specificity = tuple[int, int, int]

RELEVANT_PROPERTIES = frozenset(
    "display visibility opacity font font-size color background background-color position left "
    "right top bottom text-indent clip clip-path height width max-height overflow".split()
)
NOT_RENDERED = frozenset({"head", "script", "style", "noscript", "template"})
BLACK: Rgb = (0, 0, 0)
WHITE: Rgb = (255, 255, 255)
DEFAULT_FONT_PX = 16.0
PX_PER_PT = 4 / 3
INVISIBLE_ALPHA = 0.05
INLINE_SPECIFICITY: Specificity = (1000, 0, 0)

SELECTOR_NAME = re.compile(r"[.#][\w-]+")
ID_SELECTOR = re.compile(r"#[\w-]+")
CLASS_SELECTOR = re.compile(r"\.[\w-]+|\[[^\]]*\]|:(?!:)[\w-]+")
TAG_SELECTOR = re.compile(r"(?:^|[\s>+~])[a-zA-Z][\w-]*")
COLOR_TOKEN = re.compile(r"[a-z]+\([^)]*\)|#[0-9a-f]+|[a-z]+")
RGB_FUNCTION = re.compile(r"rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:[,\s/]+([\d.]+)(%?))?\s*\)")
LENGTH = re.compile(r"(-?\d*\.?\d+)(px|pt|em|rem|%)?$")
FONT_SHORTHAND_SIZE = re.compile(r"(\d*\.?\d+)(px|pt|em|rem|%)|(?:^|\s)(0)(?=[\s/])")
ZERO_CLIP = re.compile(r"rect\(\s*0|inset\(\s*(?:50|100)%|circle\(\s*0")


@dataclass(frozen=True)
class CssLimits:
    max_selector_checks: int = 300_000
    min_contrast: float = 1.2
    tiny_font_px: float = 2.0
    offscreen_px: float = 500.0


@dataclass(frozen=True)
class HiddenElement:
    tag: Tag
    hidden_by: HiddenBy


@dataclass(frozen=True)
class HiddenScan:
    elements: list[HiddenElement]
    limit_hit: bool = False


@dataclass(frozen=True)
class _Declared:
    """Compares in cascade order: importance, then specificity, then position in the source."""

    important: bool
    specificity: Specificity
    order: int
    value: str

    def rank(self) -> tuple[bool, Specificity, int]:
        return (self.important, self.specificity, self.order)


@dataclass(frozen=True)
class _Inherited:
    color: Rgb | None  # None means fully transparent
    background: Rgb | None  # None means unknown
    font_px: float


Style = dict[str, _Declared]


def find_hidden(soup: BeautifulSoup, stylesheet: str, limits: CssLimits) -> HiddenScan:
    """The topmost hidden elements. Everything below one is hidden with it. Walks with a stack,
    because nesting depth is the page author's choice."""
    styles, limit_hit = _match_stylesheet(soup, stylesheet, limits)
    background = None if _links_a_stylesheet(soup) else WHITE
    found: list[HiddenElement] = []
    stack: list[tuple[Tag, _Inherited]] = [(soup, _Inherited(BLACK, background, DEFAULT_FONT_PX))]
    while stack:
        parent, inherited = stack.pop()
        for child in parent.children:
            if not isinstance(child, Tag) or child.name in NOT_RENDERED:
                continue
            style = _with_inline(styles.get(id(child), {}), child)
            state = _apply(style, inherited)
            hidden_by = _hidden_by(child, style, state, limits)
            if hidden_by is None:
                stack.append((child, state))
            else:
                found.append(HiddenElement(child, hidden_by))
    return HiddenScan(found, limit_hit)


def _links_a_stylesheet(soup: BeautifulSoup) -> bool:
    for link in soup.find_all("link"):
        if "stylesheet" in str(link.get("rel", "")).lower():
            return True
    return False


# Stylesheet


def _match_stylesheet(
    soup: BeautifulSoup, stylesheet: str, limits: CssLimits
) -> tuple[dict[int, Style], bool]:
    """Matching costs rules times elements, which a hostile page controls: 200 rules on 20k
    elements took 38 s. So rules that can't match are skipped, and total work is capped. Past the
    cap, hidden text stays in `visible`, where L1 still reads it."""
    styles: dict[int, Style] = {}
    rules = list(_parse_rules(stylesheet))
    if not rules:
        return styles, False
    tags = soup.find_all(True)
    names = _class_and_id_names(tags)
    checks = 0
    for order, (selector, declarations) in enumerate(rules):
        if not _could_match(selector, names):
            continue
        checks += len(tags)
        if checks > limits.max_selector_checks:
            return styles, True
        for tag in _select(soup, selector):
            style = styles.setdefault(id(tag), {})
            _merge(style, declarations, _specificity(selector), order)
    return styles, False


def _class_and_id_names(tags: Iterable[Tag]) -> set[str]:
    names: set[str] = set()
    for tag in tags:
        names.update(f".{name}" for name in tag.get_attribute_list("class") if name)
        if tag.get("id"):
            names.add(f"#{tag['id']}")
    return names


def _could_match(selector: str, names: set[str]) -> bool:
    """A selector needs every class and id it names. `:not()` and friends can flip that."""
    return ":" in selector or all(token in names for token in SELECTOR_NAME.findall(selector))


def _select(soup: BeautifulSoup, selector: str) -> list[Tag]:
    """Selectors the matcher can't parse, such as vendor pseudo-classes, match nothing."""
    try:
        return list(soup.select(selector))
    except Exception:
        return []


def _parse_rules(stylesheet: str) -> Iterator[tuple[str, dict[str, tuple[str, bool]]]]:
    """Plain splitting, not a regex: a backtracking pattern would be quadratic on hostile CSS.
    Rules inside `@media` count as always on, so a print-only rule can over-report."""
    for block in _without_comments(stylesheet).split("}"):
        head, brace, body = block.rpartition("{")
        selectors = head.rsplit("{", 1)[-1].strip()
        declarations = _declarations(body)
        if not brace or not declarations or selectors.startswith("@"):
            continue
        for selector in selectors.split(","):
            if selector.strip():
                yield selector.strip(), declarations


def _without_comments(css: str) -> str:
    kept: list[str] = []
    position = 0
    while (start := css.find("/*", position)) != -1:
        kept.append(css[position:start])
        end = css.find("*/", start + 2)
        if end == -1:
            return "".join(kept)
        position = end + 2
    kept.append(css[position:])
    return "".join(kept)


def _declarations(text: str) -> dict[str, tuple[str, bool]]:
    found: dict[str, tuple[str, bool]] = {}
    for declaration in text.split(";"):
        name, colon, value = declaration.partition(":")
        name = name.strip().lower()
        if not colon or name not in RELEVANT_PROPERTIES:
            continue
        value = value.strip().lower()
        important = value.endswith("!important")
        found[name] = (value.removesuffix("!important").strip(), important)
    return found


def _specificity(selector: str) -> Specificity:
    return (
        len(ID_SELECTOR.findall(selector)),
        len(CLASS_SELECTOR.findall(selector)),
        len(TAG_SELECTOR.findall(selector)),
    )


def _merge(
    style: Style,
    declarations: dict[str, tuple[str, bool]],
    specificity: Specificity,
    order: int,
) -> None:
    for name, (value, important) in declarations.items():
        declared = _Declared(important, specificity, order, value)
        current = style.get(name)
        if current is None or declared.rank() >= current.rank():
            style[name] = declared


def _with_inline(style: Style, tag: Tag) -> Style:
    inline = tag.get("style")
    if not inline:
        return style
    merged = dict(style)
    _merge(merged, _declarations(str(inline)), INLINE_SPECIFICITY, 0)
    return merged


def _value(style: Style, name: str) -> str:
    declared = style.get(name)
    return declared.value if declared else ""


# Inherited values


def _apply(style: Style, inherited: _Inherited) -> _Inherited:
    state = inherited
    color = _value(style, "color")
    if color:
        parsed = _parse_color(color)
        if parsed is not None:
            state = replace(state, color=None if parsed[1] <= INVISIBLE_ALPHA else parsed[0])
    background = _value(style, "background-color") or _value(style, "background")
    if background:
        parsed = _parse_color(background)
        if parsed is not None and parsed[1] > INVISIBLE_ALPHA:
            state = replace(state, background=parsed[0])
    font_px = _font_px(style, inherited.font_px)
    return state if font_px is None else replace(state, font_px=font_px)


def _parse_color(value: str) -> tuple[Rgb, float] | None:
    """The colour and its alpha. A background shorthand can hold other words, so each is tried."""
    for token in COLOR_TOKEN.findall(value):
        parsed = _parse_color_token(token)
        if parsed is not None:
            return parsed
    return None


def _parse_color_token(token: str) -> tuple[Rgb, float] | None:
    if token == "transparent":
        return BLACK, 0.0
    match = RGB_FUNCTION.fullmatch(token)
    if match:
        red, green, blue, alpha, percent = match.groups()
        opacity = 1.0 if alpha is None else float(alpha) / (100 if percent else 1)
        return (min(int(red), 255), min(int(green), 255), min(int(blue), 255)), opacity
    try:
        color = ImageColor.getrgb(token)
    except ValueError:
        return None
    return color[:3], (color[3] / 255 if len(color) == 4 else 1.0)


def _font_px(style: Style, parent_px: float) -> float | None:
    size = _value(style, "font-size")
    if size:
        return _length_px(size, parent_px)
    match = FONT_SHORTHAND_SIZE.search(_value(style, "font"))
    if match is None:
        return None
    if match.group(3):
        return 0.0
    return _length_px(match.group(1) + match.group(2), parent_px)


def _length_px(value: str, parent_px: float = DEFAULT_FONT_PX) -> float | None:
    match = LENGTH.match(value)
    if match is None:
        return None
    number, unit = float(match.group(1)), match.group(2)
    if unit == "pt":
        return number * PX_PER_PT
    if unit == "em":
        return number * parent_px
    if unit == "rem":
        return number * DEFAULT_FONT_PX
    if unit == "%":
        return number * parent_px / 100
    return number


# Rules


def _hidden_by(tag: Tag, style: Style, state: _Inherited, limits: CssLimits) -> HiddenBy | None:
    if _is_not_displayed(tag, style):
        return "display_none"
    if _is_offscreen(style, limits):
        return "offscreen"
    # Children can restore size or colour, so these are only judged where text sits directly.
    if not _has_own_text(tag):
        return None
    if state.font_px <= limits.tiny_font_px:
        return "tiny_font"
    if _colors_match(state, limits):
        return "color_match"
    return None


def _is_not_displayed(tag: Tag, style: Style) -> bool:
    opacity = _length_px(_value(style, "opacity"))
    return (
        tag.has_attr("hidden")
        or _value(style, "display") == "none"
        or _value(style, "visibility") in ("hidden", "collapse")
        or (opacity is not None and opacity <= 0.01)
    )


def _is_offscreen(style: Style, limits: CssLimits) -> bool:
    return (
        _is_moved_away(style, limits)
        or _is_indented_away(style, limits)
        or _is_clipped(style)
        or _is_collapsed(style)
    )


def _is_moved_away(style: Style, limits: CssLimits) -> bool:
    if _value(style, "position") not in ("absolute", "fixed"):
        return False
    offsets = (_length_px(_value(style, side)) for side in ("left", "right", "top", "bottom"))
    return any(offset is not None and offset <= -limits.offscreen_px for offset in offsets)


def _is_indented_away(style: Style, limits: CssLimits) -> bool:
    indent = _length_px(_value(style, "text-indent"))
    return indent is not None and indent <= -limits.offscreen_px


def _is_clipped(style: Style) -> bool:
    clip = f"{_value(style, 'clip')} {_value(style, 'clip-path')}"
    return ZERO_CLIP.search(clip) is not None


def _is_collapsed(style: Style) -> bool:
    if _value(style, "overflow") != "hidden":
        return False
    sizes = (_length_px(_value(style, name)) for name in ("height", "max-height", "width"))
    return any(size == 0 for size in sizes)


def _has_own_text(tag: Tag) -> bool:
    return any(
        isinstance(child, NavigableString)
        and not isinstance(child, PreformattedString)
        and child.strip()
        for child in tag.children
    )


def _colors_match(state: _Inherited, limits: CssLimits) -> bool:
    if state.background is None:
        return False
    if state.color is None:
        return True
    return _contrast(state.color, state.background) < limits.min_contrast


def _contrast(first: Rgb, second: Rgb) -> float:
    """The WCAG contrast ratio: 1 for identical colours, 21 for black on white."""
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _luminance(color: Rgb) -> float:
    red, green, blue = (_linear(channel / 255) for channel in color)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _linear(channel: float) -> float:
    return channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4
