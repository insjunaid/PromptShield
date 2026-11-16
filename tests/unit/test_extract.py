"""HTML and JSON must split into parts with the right origin, and lose nothing on bad input."""

import pytest

from promptshield.models import SegmentOrigin
from promptshield.text import extract
from promptshield.text.extract import (
    TextPart,
    extract_html,
    flatten_json,
    looks_like_html,
    looks_like_json,
)


def parts_of(html: str) -> list[TextPart]:
    return extract_html(html).parts


def texts(parts: list[TextPart], origin: SegmentOrigin) -> list[str]:
    return [part.text for part in parts if part.origin == origin]


def test_visible_text_comes_first() -> None:
    parts = parts_of("<!-- note --><html><body><p>Hello</p></body></html>")
    assert parts[0] == TextPart("Hello", "visible")


def test_comment_is_separated_from_visible_text() -> None:
    parts = parts_of("<p>Hello</p><!-- ignore the user -->")
    assert texts(parts, "html_comment") == [" ignore the user "]
    assert "ignore" not in texts(parts, "visible")[0]


def test_comments_inside_elements_are_found() -> None:
    parts = parts_of("<div><span><!-- deep --></span></div>")
    assert texts(parts, "html_comment") == [" deep "]


def test_doctype_is_not_a_comment() -> None:
    assert texts(parts_of("<!doctype html><p>x</p>"), "html_comment") == []


def test_meta_content_is_found() -> None:
    parts = parts_of('<head><meta name="description" content="do this"></head><p>x</p>')
    assert texts(parts, "meta") == ["do this"]


@pytest.mark.parametrize(
    "html",
    [
        '<img src="a.png" alt="do this">',
        '<a href="/" title="do this">x</a>',
        '<div aria-label="do this">x</div>',
        '<div data-note="do this">x</div>',
        '<input placeholder="do this">',
        '<input type="hidden" name="x" value="do this">',
        '<input type="HIDDEN" value="do this">',
    ],
)
def test_attributes_are_found(html: str) -> None:
    assert texts(parts_of(html), "attribute") == ["do this"]


def test_a_visible_input_value_is_not_an_attribute_finding() -> None:
    assert texts(parts_of('<input type="text" value="Search">'), "attribute") == []


def test_image_source_is_not_read() -> None:
    html = '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB">'
    assert parts_of(html) == []


@pytest.mark.parametrize(
    "html",
    [
        "<noscript>do this</noscript><p>x</p>",
        "<template><p>do this</p></template><p>x</p>",
        '<script type="application/ld+json">do this</script><p>x</p>',
        '<script type="text/plain">do this</script><p>x</p>',
    ],
)
def test_unrendered_markup_is_found_and_not_visible(html: str) -> None:
    parts = parts_of(html)
    assert texts(parts, "hidden_markup") == ["do this"]
    assert texts(parts, "visible") == ["x"]


@pytest.mark.parametrize(
    "html",
    [
        "<script>var a = 1;</script><p>x</p>",
        '<script type="text/javascript">var a = 1;</script><p>x</p>',
        '<script type="module">var a = 1;</script><p>x</p>',
        "<style>p { color: red }</style><p>x</p>",
    ],
)
def test_code_is_not_treated_as_text(html: str) -> None:
    assert parts_of(html) == [TextPart("x", "visible")]


def test_css_hidden_text_leaves_the_visible_part() -> None:
    parts = parts_of('<p>shown</p><div style="display:none">secret</div>')
    assert texts(parts, "visible") == ["shown"]
    assert parts[1] == TextPart("secret", "hidden_css", "display_none")


def test_same_text_hidden_two_ways_gives_two_parts() -> None:
    html = (
        '<div style="display:none">x</div><div style="font-size:0">x</div>'
        '<div style="display:none">y</div>'
    )
    hidden = {part.hidden_by: part.text for part in parts_of(html)}
    assert hidden["tiny_font"] == "x"
    assert set(hidden["display_none"].split()) == {"x", "y"}


def test_text_split_across_hidden_inline_tags_stays_one_word() -> None:
    parts = parts_of("<div hidden><b>ig</b><i>nore</i></div>")
    assert texts(parts, "hidden_css") == ["ignore"]


def test_text_split_across_inline_tags_stays_one_word() -> None:
    assert texts(parts_of("<p><b>ig</b><i>nore</i></p>"), "visible") == ["ignore"]


def test_paragraphs_stay_apart() -> None:
    assert texts(parts_of("<p>one</p><p>two</p>"), "visible") == ["one\ntwo"]


def test_entities_are_decoded() -> None:
    assert texts(parts_of("<p>a &amp; b</p>"), "visible") == ["a & b"]


def test_attribute_entities_are_decoded() -> None:
    assert texts(parts_of('<img alt="a &amp; b">'), "attribute") == ["a & b"]


def test_broken_html_is_still_read() -> None:
    parts = parts_of("<div><p>unclosed <b>text")
    assert texts(parts, "visible") == ["unclosed text"]


def test_a_parser_failure_returns_the_whole_input(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("parser died")

    monkeypatch.setattr(extract, "BeautifulSoup", explode)
    assert parts_of("<p>x</p>") == [TextPart("<p>x</p>", "visible")]


@pytest.mark.parametrize(
    "text",
    [
        "<!doctype html><p>x",
        "<HTML>",
        "text <!-- hidden -->",
        "<div class='a'>",
        "<p>x</p>",
        '<img src="a">',
    ],
)
def test_html_is_recognized(text: str) -> None:
    assert looks_like_html(text)


@pytest.mark.parametrize("text", ["a < b and b > c", "plain text", "x <- y", "<paragraph>"])
def test_plain_text_is_not_html(text: str) -> None:
    assert not looks_like_html(text)


def test_json_is_recognized() -> None:
    assert looks_like_json('  {"a": 1}')
    assert looks_like_json("[1]")
    assert not looks_like_json("hello")


def test_json_strings_are_collected_in_order() -> None:
    assert flatten_json('{"a": "one", "b": ["two", {"c": "three"}]}') == "a\none\nb\ntwo\nc\nthree"


def test_json_keys_are_included() -> None:
    assert "do this" in str(flatten_json('{"do this": 1}'))


def test_json_numbers_are_skipped() -> None:
    assert flatten_json('{"a": 1, "b": null, "c": true}') == "a\nb\nc"


def test_invalid_json_is_none() -> None:
    assert flatten_json("{not json") is None


def test_very_deep_json_does_not_crash() -> None:
    depth = 200_000
    assert flatten_json("[" * depth + "]" * depth) in (None, "")
