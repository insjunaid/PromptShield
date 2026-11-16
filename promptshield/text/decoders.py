"""Finds encoded blobs that decode to readable text, so a classifier can read the plain version.

Real pages are full of hashes and ids that fit the same patterns. Those decode to binary, which is
why only output that reads as text is kept.
"""

import base64
import binascii
import codecs
import re
from collections.abc import Iterator
from typing import NamedTuple
from urllib.parse import unquote_plus

# ROT13 has no charset of its own, since it looks like letters. So it's judged by whether decoding
# turns text with few common words into text with many.
COMMON_WORDS = frozenset(
    "a all and are as at be before do file first for from in instructions is it not of on or "
    "read send that the then this to use with you your".split()
)
MIN_COMMON_WORDS = 3
MIN_URL_ESCAPES = 3
LOWER_WORD = re.compile(r"[a-z]+")
WHITESPACE = "\n\r\t"


class Payload(NamedTuple):
    text: str  # the decoded text
    encoding: str
    offset: int  # where the encoded blob starts
    length: int  # how long the encoded blob is, so it can be cut out


class PayloadFinder:
    def __init__(self, min_length: int, printable_ratio: float) -> None:
        self._printable_ratio = printable_ratio
        self._base64 = re.compile(rf"[A-Za-z0-9+/_-]{{{min_length},}}={{0,2}}")
        self._hex = re.compile(rf"(?:[0-9a-fA-F]{{2}}){{{(min_length + 1) // 2},}}")
        self._url = re.compile(rf"(?:%[0-9a-fA-F]{{2}}|[A-Za-z0-9_.~+-]){{{min_length},}}")
        self._rot13 = re.compile(rf"[A-Za-z][A-Za-z ,.'\":;!?-]{{{min_length - 1},}}")

    def find(self, text: str) -> Iterator[Payload]:
        """Yield each blob that decodes to readable text."""
        for match in self._base64.finditer(text):
            yield from self._readable(_from_base64(match.group()), "base64", match)
        for match in self._hex.finditer(text):
            yield from self._readable(bytes.fromhex(match.group()), "hex", match)
        for match in self._url.finditer(text):
            yield from self._url_payload(match)
        for match in self._rot13.finditer(text):
            yield from _rot13_payload(match)

    def _readable(
        self, data: bytes | None, encoding: str, match: re.Match[str]
    ) -> Iterator[Payload]:
        if data is None:
            return
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return
        if self._reads_as_text(text):
            yield Payload(text, encoding, match.start(), len(match.group()))

    def _reads_as_text(self, text: str) -> bool:
        printable = sum(char.isprintable() or char in WHITESPACE for char in text)
        has_letters = any(char.isalpha() for char in text)
        return has_letters and printable / len(text) >= self._printable_ratio

    def _url_payload(self, match: re.Match[str]) -> Iterator[Payload]:
        blob = match.group()
        if blob.count("%") < MIN_URL_ESCAPES:
            return
        try:
            text = unquote_plus(blob, errors="strict")
        except UnicodeDecodeError:
            return
        if self._reads_as_text(text):
            yield Payload(text, "url", match.start(), len(blob))


def _from_base64(blob: str) -> bytes | None:
    """Accepts the URL-safe alphabet and missing padding, both common in the wild."""
    body = blob.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except binascii.Error:
        return None


def _rot13_payload(match: re.Match[str]) -> Iterator[Payload]:
    blob = match.group()
    decoded = codecs.decode(blob, "rot13")
    hits = _common_words(decoded)
    if hits >= MIN_COMMON_WORDS and hits > _common_words(blob):
        yield Payload(decoded, "rot13", match.start(), len(blob))


def _common_words(text: str) -> int:
    return sum(word in COMMON_WORDS for word in LOWER_WORD.findall(text.lower()))
