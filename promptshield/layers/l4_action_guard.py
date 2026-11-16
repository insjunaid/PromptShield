"""L4: checks a tool call before it runs. This is where containment happens.

The policy engine holds the rules. This guard gathers the facts it needs: taint and counts from the
session, canaries, DLP, and optionally whether the action fits the user's task. If gathering fails,
the call is blocked: for actions, the shield always fails closed.
"""

import asyncio
import json
import math
import re
from collections import Counter
from typing import Any, Protocol

import httpx
import structlog
from pydantic import ValidationError

from promptshield.config import Settings
from promptshield.layers.canary import CanaryStore
from promptshield.models import Schema, ToolCall, Verdict
from promptshield.policy.engine import OutboundSignals, PolicyEngine
from promptshield.redact import PRIVATE_KEY, SECRET_PATTERNS
from promptshield.sessions import SessionStore
from promptshield.taint import strings_in

logger = structlog.get_logger(__name__)

TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
# Only identifiers worth stopping. Names, dates and phone numbers fire on ordinary email text.
PRESIDIO_ENTITIES = ("CREDIT_CARD", "US_SSN", "IBAN_CODE", "CRYPTO", "US_BANK_NUMBER")
PRESIDIO_MIN_SCORE = 0.5
ALIGNMENT_CLASSES = frozenset({"egress", "write"})


def shannon_entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(count / len(text) * math.log2(count / len(text)) for count in counts.values())


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def _looks_random(token: str, min_entropy: float) -> bool:
    """A random key mixes character kinds. Long words and repeated characters don't."""
    kinds = sum(bool(re.search(pattern, token)) for pattern in (r"[a-z]", r"[A-Z]", r"\d"))
    return kinds >= 2 and shannon_entropy(token) >= min_entropy


class PiiDetector(Protocol):
    def find(self, text: str) -> list[str]: ...


class PresidioDetector:
    """Optional. It adds about 400 MB and a 12 s load (D053), so it's off by default."""

    def __init__(self) -> None:
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import-not-found]
        from presidio_analyzer.nlp_engine import (  # type: ignore[import-not-found]
            NlpEngineProvider,
        )

        config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        nlp = NlpEngineProvider(nlp_configuration=config).create_engine()
        self._engine = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])

    def find(self, text: str) -> list[str]:
        results = self._engine.analyze(text=text, language="en", entities=list(PRESIDIO_ENTITIES))
        return sorted(
            {result.entity_type for result in results if result.score >= PRESIDIO_MIN_SCORE}
        )


class Dlp:
    """Names what it found, never the value: findings are stored and shown."""

    def __init__(self, settings: Settings, pii: PiiDetector | None = None) -> None:
        self._min_entropy = settings.dlp_min_entropy
        self._use_presidio = settings.dlp_presidio
        self._pii = pii

    def hits(self, args: Any) -> list[str]:
        found: set[str] = set()
        for text in strings_in(args):
            found.update(self._in_text(text))
        return sorted(found)

    def _in_text(self, text: str) -> set[str]:
        found: set[str] = set()
        if PRIVATE_KEY.search(text):
            found.add("private key")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            found.add("secret key")
        if any(_looks_random(token, self._min_entropy) for token in TOKEN.findall(text)):
            found.add("high-entropy string")
        for match in CARD.finditer(text):
            digits = re.sub(r"\D", "", match.group())
            if luhn_valid(digits):
                found.add("card number")
        found.update(self._presidio().find(text) if self._use_presidio else [])
        return found

    def _presidio(self) -> PiiDetector:
        if self._pii is None:
            self._pii = PresidioDetector()
        return self._pii


class AlignmentAnswer(Schema):
    reason: str
    aligned: bool


ALIGNMENT_PROMPT = (
    "An AI agent was given a task by its user. It now wants to call a tool. Decide whether the "
    "call plausibly serves the user's task. Sending data to people or places the task never "
    "mentions, or deleting things the task didn't ask to delete, does not serve it. Answer only "
    "with the JSON object asked for, with a one-sentence reason first."
)


class ActionGuard:
    def __init__(
        self,
        settings: Settings,
        engine: PolicyEngine,
        sessions: SessionStore,
        canaries: CanaryStore,
        dlp: Dlp,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._engine = engine
        self._sessions = sessions
        self._canaries = canaries
        self._dlp = dlp
        self._transport = transport

    async def evaluate(self, tool_call: ToolCall, user_task: str | None = None) -> Verdict:
        """Never raises. Any failure while gathering facts blocks the call (fail closed)."""
        if "L4" not in self._settings.enabled_layers:
            return self._engine.outbound_skipped()
        try:
            signals = await self._signals(tool_call, user_task)
        except Exception as error:
            # Only the type: the message could quote arguments, which may hold secrets.
            logger.error("action_guard_failed", error=type(error).__name__)
            signals = OutboundSignals(tool_call=tool_call, guard_failed=True)
        return self._engine.decide_outbound(signals)

    async def _signals(self, tool_call: ToolCall, user_task: str | None) -> OutboundSignals:
        tool_class = self._engine.classify_tool(tool_call)
        state = self._sessions.get(tool_call.session_id)
        signals = state.signals_for(tool_call, tool_class)
        dlp = await asyncio.to_thread(self._dlp.hits, tool_call.args)
        canary = await asyncio.to_thread(self._canaries.in_arguments, tool_call.args)
        misaligned = False
        if self._settings.task_alignment and user_task and tool_class in ALIGNMENT_CLASSES:
            misaligned = await self._misaligned(tool_call, user_task)
        return signals.model_copy(
            update={"canary_hit": canary, "dlp_hit": bool(dlp), "misaligned": misaligned}
        )

    async def _misaligned(self, tool_call: ToolCall, user_task: str) -> bool:
        """Ollama not running skips the check with a warning: the other rules still stand. A
        broken answer counts as misaligned, which asks a human rather than guessing."""
        settings = self._settings
        call = json.dumps({"tool": f"{tool_call.server}.{tool_call.tool}", "args": tool_call.args})
        body = {
            "model": settings.judge_model,
            "messages": [
                {"role": "system", "content": ALIGNMENT_PROMPT},
                {"role": "user", "content": f"User's task: {user_task!r}\nTool call: {call}"},
            ],
            "stream": False,
            "think": settings.think,
            "format": AlignmentAnswer.model_json_schema(),
            "keep_alive": settings.judge_keep_alive,
            "options": {"temperature": 0, "num_ctx": settings.num_ctx, "num_predict": 120},
        }
        async with httpx.AsyncClient(
            transport=self._transport, timeout=settings.judge_timeout_seconds, trust_env=False
        ) as client:
            try:
                response = await client.post(f"{settings.ollama_url}/api/chat", json=body)
            except httpx.ConnectError:
                logger.warning("task_alignment_skipped", reason="Ollama is not running")
                return False
        response.raise_for_status()
        try:
            answer = AlignmentAnswer.model_validate_json(response.json()["message"]["content"])
        except (KeyError, TypeError, ValueError, ValidationError):
            logger.warning("task_alignment_malformed")
            return True
        return not answer.aligned
