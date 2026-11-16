"""Removes secrets from anything that gets stored or shown.

Redaction runs before truncation, because cutting a secret in half would stop the pattern matching
and leave the first half in clear. Encoded secrets (base64, reversed) are not caught here: canary
detection handles those variants.
"""

import re
from typing import Any, TypeVar

from pydantic import BaseModel

TRUNCATION_MARK = "…[truncated]"
BINARY_PLACEHOLDER = "[binary content omitted]"
LITERAL_PLACEHOLDER = "[redacted]"

ModelT = TypeVar("ModelT", bound=BaseModel)


def _keep_last_four(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    return f"{prefix}…{match.group('secret')[-4:]}"


# Each pattern keeps a short prefix, so the dashboard can show what kind of secret it was.
SECRET_PATTERNS = (
    re.compile(r"(?P<prefix>\bsk-canary-)(?P<secret>[A-Za-z0-9_-]{4,})"),
    re.compile(r"(?P<prefix>\bsk-)(?!canary-)(?P<secret>[A-Za-z0-9_-]{8,})"),
    re.compile(r"(?P<prefix>\bhf_)(?P<secret>[A-Za-z0-9]{20,})"),
    re.compile(r"(?P<prefix>\bgh[pousr]_)(?P<secret>[A-Za-z0-9]{20,})"),
    re.compile(r"(?P<prefix>\bAKIA)(?P<secret>[0-9A-Z]{16})\b"),
    re.compile(r"(?P<prefix>\beyJ)(?P<secret>[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,})"),
    re.compile(r"(?P<prefix>\bBearer\s+)(?P<secret>[A-Za-z0-9._~+/=-]{16,})"),
)
PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL
)


class Redactor:
    """Masks known secret shapes, plus exact values registered at runtime (such as canaries)."""

    def __init__(self, text_limit: int = 20000) -> None:
        self._text_limit = text_limit
        self._literals: set[str] = set()

    def add_secret(self, value: str) -> None:
        """Register an exact value, for secrets with no recognizable shape like a fake password."""
        if value:
            self._literals.add(value)

    def scrub_text(self, text: str) -> str:
        for literal in self._literals:
            text = text.replace(literal, LITERAL_PLACEHOLDER)
        text = PRIVATE_KEY.sub("[redacted private key]", text)
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(_keep_last_four, text)
        if len(text) > self._text_limit:
            text = text[: self._text_limit - len(TRUNCATION_MARK)] + TRUNCATION_MARK
        return text

    def scrub_value(self, value: Any) -> Any:
        """Scrub every string in a JSON-like value, including dictionary keys."""
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, list):
            return [self.scrub_value(item) for item in value]
        if isinstance(value, dict):
            if value.get("data_is_base64"):
                return self._without_binary(value)
            return {self.scrub_value(key): self.scrub_value(item) for key, item in value.items()}
        return value

    def scrub_model(self, model: ModelT) -> ModelT:
        """Return a scrubbed copy. Raises if the result no longer validates."""
        return type(model).model_validate(self.scrub_value(model.model_dump(mode="json")))

    def _without_binary(self, item: dict[str, Any]) -> dict[str, Any]:
        """Replace a base64 content item, because binary can't be scanned or safely truncated."""
        scrubbed = {key: self.scrub_value(value) for key, value in item.items() if key != "data"}
        return scrubbed | {"kind": "text", "data": BINARY_PLACEHOLDER, "data_is_base64": False}
