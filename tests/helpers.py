"""Shared test doubles."""

from collections.abc import Sequence
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class ScriptedModel(BaseChatModel):
    """Plays back fixed replies and records what it was shown."""

    replies: list[AIMessage]
    seen: list[list[BaseMessage]] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> "ScriptedModel":
        return self

    def _generate(self, messages: list[BaseMessage], *args: Any, **kwargs: Any) -> ChatResult:
        self.seen.append(list(messages))
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        # A fresh copy each time, like a real model. LangGraph merges messages that share an id.
        fresh = reply.model_copy(deep=True, update={"id": None})
        return ChatResult(generations=[ChatGeneration(message=fresh)])


def tool_call(name: str, call_id: str = "c1", **args: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


def scripted(*replies: AIMessage) -> ScriptedModel:
    return ScriptedModel(replies=list(replies), seen=[])
