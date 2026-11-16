"""Removes the Unicode tricks that hide text from people or from classifiers.

The same characters are normal in other contexts: ZWJ builds emoji, ZWNJ is needed in Hindi and
Persian, and direction marks are routine in Arabic. Flagging those would punish non-English pages,
so context decides what counts as a trick.
"""

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

import ftfy

TAG_BASE = 0xE0000
TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
BLACK_FLAG = "\U0001f3f4"
# A subdivision flag spells a short lowercase region code and ends with the cancel tag. The length
# limit matters: without it, a long message after a black flag would pass as "an emoji".
EMOJI_TAGS = re.compile("[\U000e0030-\U000e0039\U000e0061-\U000e007a]{2,6}\U000e007f")

SOFT_HYPHEN = "­"
BOM = "﻿"
JOINERS = frozenset("​‌‍")
DIRECTION_MARKS = frozenset("‎‏")
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
INVISIBLE = re.compile("[­͏᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]")
RTL_WINDOW_CHARS = 32

# Scripts that use joiners for ordinary spelling or word breaks.
JOINER_SCRIPT_RANGES = (
    (0x0590, 0x08FF),  # Hebrew, Arabic, Syriac, Thaana
    (0x0900, 0x109F),  # Indic scripts, Thai, Lao, Tibetan, Myanmar
    (0x1780, 0x17FF),  # Khmer
    (0xFB1D, 0xFDFF),  # Hebrew and Arabic presentation forms
    (0xFE70, 0xFEFC),  # Arabic presentation forms
)
VARIATION_SELECTOR_16 = 0xFE0F
EMOJI_RANGE = (0x1F000, 0x1FFFF)

# Two distinct marks can carry bits. Below four bytes, a decoded "message" is likely chance.
MIN_MESSAGE_MARKS = 32
BITS_PER_CHAR = 8
MESSAGE_SYMBOLS = 2

WORD = re.compile(r"[^\W\d_]{3,}")
LATIN_LOOKALIKES = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "І": "I",
    "Ј": "J",
    "Ѕ": "S",
    # Greek
    "α": "a",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "υ": "u",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}
LOOKALIKE_TABLE = str.maketrans(LATIN_LOOKALIKES)


@dataclass(frozen=True)
class CleanText:
    """Text as a classifier should read it, plus what was hidden in it."""

    text: str
    tag_message: str = ""
    zero_width_message: str = ""
    zero_width_count: int = 0
    bidi_count: int = 0
    confusable_words: tuple[str, ...] = ()


def clean_text(text: str) -> CleanText:
    """Mojibake is fixed first, because a broken page can spell these characters as mojibake."""
    if text.isascii():
        return CleanText(text=text)
    fixed = ftfy.fix_encoding(text)
    without_tags, tag_message = _extract_tags(fixed)
    visible, marks, bidi_count = _strip_invisible(without_tags)
    normalized = unicodedata.normalize("NFKC", visible)
    readable, words = _fix_confusables(normalized)
    return CleanText(
        text=readable,
        tag_message=tag_message,
        zero_width_message=_hidden_message(marks),
        zero_width_count=len(marks),
        bidi_count=bidi_count,
        confusable_words=tuple(words),
    )


def _extract_tags(text: str) -> tuple[str, str]:
    """Runs are joined, because a message can be split up between visible letters."""
    decoded: list[str] = []

    def replace(match: re.Match[str]) -> str:
        run = match.group()
        after_flag = match.start() > 0 and text[match.start() - 1] == BLACK_FLAG
        if after_flag and EMOJI_TAGS.fullmatch(run):
            return run
        decoded.extend(_tag_to_ascii(run))
        return ""

    return TAG_RUN.sub(replace, text), "".join(decoded)


def _tag_to_ascii(run: str) -> list[str]:
    characters = (chr(ord(character) - TAG_BASE) for character in run)
    return [character for character in characters if character.isprintable()]


def _strip_invisible(text: str) -> tuple[str, list[str], int]:
    marks: list[str] = []
    bidi_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal bidi_count
        character, index = match.group(), match.start()
        if character == SOFT_HYPHEN or (character == BOM and index == 0):
            return ""  # Routine in real pages, and it would still split words for a classifier.
        if _is_legitimate(text, index):
            return character
        if character in BIDI_CONTROLS:
            bidi_count += 1
        else:
            marks.append(character)
        return ""

    return INVISIBLE.sub(replace, text), marks, bidi_count


def _is_legitimate(text: str, index: int) -> bool:
    character = text[index]
    if character in JOINERS:
        return _next_to_joining_text(text, index)
    if character in DIRECTION_MARKS or character in BIDI_CONTROLS:
        return _near_rtl_text(text, index)
    return False


def _next_to_joining_text(text: str, index: int) -> bool:
    neighbours = text[max(index - 1, 0) : index] + text[index + 1 : index + 2]
    return any(_uses_joiners(character) or _is_emoji(character) for character in neighbours)


def _uses_joiners(character: str) -> bool:
    code = ord(character)
    return any(start <= code <= end for start, end in JOINER_SCRIPT_RANGES)


def _is_emoji(character: str) -> bool:
    code = ord(character)
    return (
        EMOJI_RANGE[0] <= code <= EMOJI_RANGE[1]
        or code == VARIATION_SELECTOR_16
        or unicodedata.category(character) == "So"
    )


def _near_rtl_text(text: str, index: int) -> bool:
    """Letters only: RLM itself has right-to-left class, and would otherwise excuse itself."""
    nearby = text[max(index - RTL_WINDOW_CHARS, 0) : index + RTL_WINDOW_CHARS]
    return any(
        character.isalpha() and unicodedata.bidirectional(character) in ("R", "AL")
        for character in nearby
    )


def _hidden_message(marks: Sequence[str]) -> str:
    """Decode marks used as bits. Either mark could mean 1, so both readings are tried."""
    symbols = sorted(set(marks))
    if (
        len(symbols) != MESSAGE_SYMBOLS
        or len(marks) < MIN_MESSAGE_MARKS
        or len(marks) % BITS_PER_CHAR
    ):
        return ""
    for one in symbols:
        bits = "".join("1" if mark == one else "0" for mark in marks)
        groups = (bits[i : i + BITS_PER_CHAR] for i in range(0, len(bits), BITS_PER_CHAR))
        message = "".join(chr(int(group, 2)) for group in groups)
        if message.isascii() and message.isprintable():
            return message
    return ""


def _fix_confusables(text: str) -> tuple[str, list[str]]:
    """Only mixed words count: a word that is all Cyrillic is just Cyrillic."""
    if text.isascii():
        return text, []
    words: list[str] = []

    def replace(match: re.Match[str]) -> str:
        word = match.group()
        foreign = [character for character in word if not character.isascii()]
        mixed = 0 < len(foreign) < len(word)
        if not mixed or any(character not in LATIN_LOOKALIKES for character in foreign):
            return word
        words.append(word)
        return word.translate(LOOKALIKE_TABLE)

    return WORD.sub(replace, text), words
