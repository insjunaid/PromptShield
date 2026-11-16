"""Splits text into overlapping windows that fit a classifier's context.

Anything past the context is silently cut off by the classifier, which would make padding a free
bypass. So token counts are deliberately pessimistic here: L0 has no tokenizer, and the real count
must never exceed the estimate. Overlap keeps a phrase that falls on a boundary whole in one window.
"""

from typing import NamedTuple

# Only cut at a space if that keeps most of the window.
MIN_FILL_FOR_SOFT_BREAK = 0.8


class Chunk(NamedTuple):
    text: str
    offset: int


def estimate_tokens(text: str, chars_per_token: int) -> int:
    """Upper-bound estimate: each non-ASCII character is counted as a full token."""
    return -(-sum(_cost(char, chars_per_token) for char in text) // chars_per_token)


def chunk_text(
    text: str, max_tokens: int, overlap_tokens: int, chars_per_token: int = 2
) -> list[Chunk]:
    """Windows of at most `max_tokens`, each sharing about `overlap_tokens` with the previous."""
    if not 0 <= overlap_tokens < max_tokens:
        raise ValueError("overlap must be smaller than the window")
    budget = max_tokens * chars_per_token
    overlap = overlap_tokens * chars_per_token
    chunks: list[Chunk] = []
    start = 0
    while start < len(text):
        end = _window_end(text, start, budget, chars_per_token)
        chunks.append(Chunk(text[start:end], start))
        if end == len(text):
            break
        start = max(_overlap_start(text, end, overlap, chars_per_token), start + 1)
    return chunks


def _cost(char: str, chars_per_token: int) -> int:
    return 1 if char.isascii() else chars_per_token


def _window_end(text: str, start: int, budget: int, chars_per_token: int) -> int:
    end, spent = start, 0
    while end < len(text):
        spent += _cost(text[end], chars_per_token)
        if spent > budget:
            break
        end += 1
    end = max(end, start + 1)  # One character always fits, or the loop would never advance.
    return end if end == len(text) else _soft_break(text, start, end)


def _soft_break(text: str, start: int, end: int) -> int:
    earliest = start + int((end - start) * MIN_FILL_FOR_SOFT_BREAK)
    space = max(text.rfind(" ", earliest, end), text.rfind("\n", earliest, end))
    return space + 1 if space > start else end


def _overlap_start(text: str, end: int, overlap: int, chars_per_token: int) -> int:
    start, spent = end, 0
    while start > 0:
        spent += _cost(text[start - 1], chars_per_token)
        if spent > overlap:
            break
        start -= 1
    return start
