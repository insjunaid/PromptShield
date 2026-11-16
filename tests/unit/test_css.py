"""A person's view of the page, worked out from styles. A positive and a negative for each rule."""

from time import perf_counter

import pytest

from promptshield.text.css import CssLimits
from promptshield.text.extract import HtmlContent, extract_html


def hidden_by(html: str) -> dict[str | None, str]:
    return {
        part.hidden_by: part.text
        for part in extract_html(html).parts
        if part.origin == "hidden_css"
    }


def is_hidden(html: str, reason: str) -> bool:
    return reason in hidden_by(html)


def visible(html: str) -> str:
    return " ".join(part.text for part in extract_html(html).parts if part.origin == "visible")


@pytest.mark.parametrize(
    "style",
    [
        "display:none",
        "DISPLAY : NONE",
        "visibility:hidden",
        "visibility:collapse",
        "opacity:0",
        "opacity:0.0",
        "display:none !important",
    ],
)
def test_display_none_positive(style: str) -> None:
    assert is_hidden(f'<div style="{style}">x</div>', "display_none")


def test_hidden_attribute_counts() -> None:
    assert is_hidden("<div hidden>x</div>", "display_none")


@pytest.mark.parametrize(
    "style", ["display:block", "visibility:visible", "opacity:0.8", "opacity:1", "color:red"]
)
def test_display_none_negative(style: str) -> None:
    assert hidden_by(f'<div style="{style}">x</div>') == {}


@pytest.mark.parametrize(
    "style",
    [
        "font-size:0",
        "font-size:0px",
        "font-size:1px",
        "font-size:2px",
        "font-size:1pt",
        "font-size:0.1em",
        "font-size:0.05rem",
        "font-size:1%",
        "font:0/0 a",
        "font:1px arial",
    ],
)
def test_tiny_font_positive(style: str) -> None:
    assert is_hidden(f'<p style="{style}">x</p>', "tiny_font")


@pytest.mark.parametrize(
    "style", ["font-size:12px", "font-size:0.8em", "font-size:90%", "font:700 12px/1.5 arial"]
)
def test_tiny_font_negative(style: str) -> None:
    assert hidden_by(f'<p style="{style}">x</p>') == {}


def test_tiny_font_is_inherited() -> None:
    assert is_hidden('<div style="font-size:0"><p>x</p></div>', "tiny_font")


def test_a_child_can_restore_the_font_size() -> None:
    assert hidden_by('<div style="font-size:0"><p style="font-size:14px">x</p></div>') == {}


def test_relative_size_uses_the_parent() -> None:
    assert is_hidden('<div style="font-size:4px"><p style="font-size:50%">x</p></div>', "tiny_font")


@pytest.mark.parametrize(
    "style",
    [
        "color:#ffffff;background:#ffffff",
        "color:#fff",  # on the default white page
        "color:white",
        "color:rgb(255,255,255)",
        "color:rgb(255 255 255)",
        "color:#fefefe;background-color:#ffffff",
        "color:#000;background:#000",
        "color:#123456;background:#123457",
        "color:transparent",
        "color:rgba(0,0,0,0)",
        "color:#00000000",
        "color:hsl(0,0%,100%)",
        "color:#eee;background:#f0f0f0 url(a.png) no-repeat",
    ],
)
def test_color_match_positive(style: str) -> None:
    assert is_hidden(f'<p style="{style}">x</p>', "color_match")


@pytest.mark.parametrize(
    "style",
    [
        "color:#777",  # legit grey text
        "color:#999;background:#fff",
        "color:#fff;background:#000",
        "color:black",
        "color:rgba(0,0,0,0.6)",
        "color:inherit",
        "color:notacolor",
    ],
)
def test_color_match_negative(style: str) -> None:
    assert hidden_by(f'<p style="{style}">x</p>') == {}


def test_background_is_inherited() -> None:
    html = '<div style="background:#000"><p style="color:#000">x</p></div>'
    assert is_hidden(html, "color_match")


def test_color_is_inherited() -> None:
    assert is_hidden('<div style="color:#fff"><p>x</p></div>', "color_match")


def test_dark_theme_is_not_hidden() -> None:
    html = '<body style="background:#111;color:#eee"><p>x</p></body>'
    assert hidden_by(html) == {}


def test_a_visible_child_of_a_white_parent_stays_visible() -> None:
    html = '<div style="color:#fff"><p style="color:#000">shown</p></div>'
    assert visible(html) == "shown"


def test_an_external_stylesheet_means_the_background_is_unknown() -> None:
    """White text is normal on a dark background set in a file we didn't fetch."""
    html = '<link rel="stylesheet" href="s.css"><p style="color:#fff">x</p>'
    assert hidden_by(html) == {}


def test_matching_colors_with_an_external_stylesheet_are_still_caught() -> None:
    html = '<link rel="stylesheet" href="s.css"><p style="color:#fff;background:#fff">x</p>'
    assert is_hidden(html, "color_match")


@pytest.mark.parametrize(
    "style",
    [
        "position:absolute;left:-9999px",
        "position:fixed;top:-5000px",
        "position:absolute;right:-1000px",
        "text-indent:-9999px",
        "clip:rect(0,0,0,0)",
        "clip:rect(0 0 0 0)",
        "clip-path:inset(100%)",
        "clip-path:inset(50%)",
        "clip-path:circle(0)",
        "height:0;overflow:hidden",
        "max-height:0;overflow:hidden",
        "width:0px;overflow:hidden",
    ],
)
def test_offscreen_positive(style: str) -> None:
    assert is_hidden(f'<div style="{style}">x</div>', "offscreen")


@pytest.mark.parametrize(
    "style",
    [
        "position:absolute;left:10px",
        "position:relative;left:-9999px",  # not positioned the same way
        "position:absolute;left:-20px",
        "text-indent:-1em",
        "text-indent:20px",
        "height:0",
        "overflow:hidden",
        "height:100px;overflow:hidden",
        "clip-path:circle(50%)",
    ],
)
def test_offscreen_negative(style: str) -> None:
    assert hidden_by(f'<div style="{style}">x</div>') == {}


def test_style_block_rule_applies() -> None:
    assert is_hidden("<style>.note{display:none}</style><p class=note>x</p>", "display_none")


def test_style_block_color_applies() -> None:
    html = "<style>body{background:#fff} #n{color:#fff}</style><p id=n>x</p>"
    assert is_hidden(html, "color_match")


def test_selector_lists_apply_to_each() -> None:
    html = "<style>.a,.b{display:none}</style><p class=b>x</p>"
    assert is_hidden(html, "display_none")


def test_rule_inside_media_counts() -> None:
    html = "<style>@media screen { .n { display:none } }</style><p class=n>x</p>"
    assert is_hidden(html, "display_none")


def test_a_css_comment_is_not_a_rule() -> None:
    assert hidden_by("<style>/* .n{display:none} */</style><p class=n>x</p>") == {}


def test_higher_specificity_wins_over_later_source_order() -> None:
    """The bypass this guards against: a later, weaker rule that only looks like it wins."""
    html = "<style>#n{display:none} p{display:block}</style><p id=n>x</p>"
    assert is_hidden(html, "display_none")


def test_later_rule_wins_at_equal_specificity() -> None:
    assert hidden_by("<style>.n{display:none} .n{display:block}</style><p class=n>x</p>") == {}


def test_important_beats_specificity() -> None:
    html = "<style>.n{display:none !important} #m{display:block}</style><p id=m class=n>x</p>"
    assert is_hidden(html, "display_none")


def test_inline_beats_the_stylesheet() -> None:
    html = '<style>.n{display:none}</style><p class=n style="display:block">x</p>'
    assert hidden_by(html) == {}


def test_important_stylesheet_beats_inline() -> None:
    html = '<style>.n{display:none !important}</style><p class=n style="display:block">x</p>'
    assert is_hidden(html, "display_none")


def test_a_bad_selector_is_ignored() -> None:
    assert visible("<style>::-moz-weird(({display:none} p{color:red}</style><p>x</p>") == "x"


def test_everything_below_a_hidden_element_goes_with_it() -> None:
    html = '<div style="display:none"><div><p>deep</p></div></div><p>shown</p>'
    assert hidden_by(html) == {"display_none": "deep"}
    assert visible(html) == "shown"


def test_an_empty_hidden_element_gives_no_part() -> None:
    assert hidden_by('<div style="display:none"></div><p>x</p>') == {}


def test_too_much_selector_work_is_reported() -> None:
    rules = "p{display:none}" * 5
    content = extract_html(f"<style>{rules}</style><p>x</p>", CssLimits(max_selector_checks=3))
    assert content.css_limit_hit


def test_past_the_limit_hidden_text_stays_readable() -> None:
    """It can't be classified as hidden, but it must not disappear from the scan."""
    content = extract_html(
        "<style>p{display:none}</style><p>x</p>", CssLimits(max_selector_checks=1)
    )
    assert [part.text for part in content.parts] == ["x"]


def test_hostile_stylesheet_stays_fast() -> None:
    """Regression: 200 rules on 20k elements took 38 s."""
    rules = "".join(f"div p:nth-child({index}){{display:none}}" for index in range(1, 2000))
    started = perf_counter()
    content = extract_html(f"<style>{rules}</style>" + "<div><p>x</p></div>" * 10000)
    assert content.css_limit_hit
    assert perf_counter() - started < 15


def test_rules_for_absent_classes_cost_nothing() -> None:
    rules = "".join(f".a{index}{{display:none}}" for index in range(50000))
    page = f"<style>{rules}.n{{display:none}}</style><p class=n>x</p>"
    content = extract_html(page, CssLimits(max_selector_checks=10))
    assert not content.css_limit_hit
    assert content.parts[0].hidden_by == "display_none"


def test_a_negated_selector_is_not_skipped() -> None:
    assert is_hidden("<style>p:not(.absent){display:none}</style><p>x</p>", "display_none")


def test_within_the_rule_limit_nothing_is_reported() -> None:
    assert not extract_html("<style>.a{display:none}</style><p>x</p>").css_limit_hit


def test_rules_that_cannot_hide_text_do_not_use_up_the_limit() -> None:
    rules = "p{margin:0;padding:1px}" * 500
    html = f"<style>{rules}.n{{display:none}}</style><p class=n>x</p>"
    content = extract_html(html, CssLimits(max_selector_checks=10))
    assert not content.css_limit_hit
    assert isinstance(content, HtmlContent)
    assert content.parts[0].hidden_by == "display_none"


def test_unterminated_css_is_survived() -> None:
    assert visible("<style>/* never closed .a{display:none</style><p>x</p>") == "x"
