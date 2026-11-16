"""Information-flow labels for one session, in the spirit of CaMeL.

Every tool result is untrusted, labeled with its source. Sensitive results (file contents, emails)
are also remembered as fingerprints, so an egress call that carries that data can be caught even
when no detector noticed the attack that caused it.

Only hashes are kept, never the text: a store of fingerprints can't leak the secrets it guards.
Matching is on exact normalized text, so encoded or paraphrased copies need the canary check (P4.2)
and DLP (P4.3).
"""

import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

WORD = re.compile(r"\w+", re.UNICODE)
# A run of non-space characters that looks like a key or password: long, with a digit or a symbol.
KEY_LIKE = re.compile(r"\S{12,}")
KEY_HINT = re.compile(r"[\d\W_]")
DIGEST_BYTES = 8


@dataclass(frozen=True)
class TaintSettings:
    shingle_words: int = 5
    max_fingerprints: int = 50_000


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()[:DIGEST_BYTES]


def fingerprints(text: str, shingle_words: int) -> Iterator[bytes]:
    """Word shingles catch a copied passage. Key-like tokens catch a lone secret, which is too
    short to make a shingle. Case and spacing don't matter."""
    words = [word.lower() for word in WORD.findall(text)]
    for start in range(max(len(words) - shingle_words + 1, 0)):
        yield _digest(" ".join(words[start : start + shingle_words]))
    for token in KEY_LIKE.findall(text):
        if KEY_HINT.search(token):
            yield _digest(token.lower().strip(".,;:!?\"'()[]{}<>"))


def strings_in(value: Any) -> Iterator[str]:
    """Every string in tool arguments, however deeply nested. Keys too: they are attacker-chosen
    in a tool call made under injection."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list | tuple):
            stack.extend(item)


@dataclass
class TaintTracker:
    settings: TaintSettings = field(default_factory=TaintSettings)
    untrusted_sources: list[str] = field(default_factory=list)
    _sensitive: set[bytes] = field(default_factory=set)
    overflowed: bool = False

    @property
    def tainted(self) -> bool:
        """True once the session has read any tool output."""
        return bool(self.untrusted_sources)

    def record(self, source: str, texts: Iterable[str], sensitive: bool) -> None:
        self.untrusted_sources.append(source)
        if not sensitive:
            return
        for text in texts:
            for fingerprint in fingerprints(text, self.settings.shingle_words):
                if len(self._sensitive) >= self.settings.max_fingerprints:
                    self.overflowed = True
                    return
                self._sensitive.add(fingerprint)

    def carries_sensitive_data(self, args: Any) -> bool:
        """When the store has overflowed, the answer is yes: it can't rule a match out."""
        if self.overflowed:
            return True
        return any(
            fingerprint in self._sensitive
            for text in strings_in(args)
            for fingerprint in fingerprints(text, self.settings.shingle_words)
        )
