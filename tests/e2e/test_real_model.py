"""Checks against the real local model. Slow: run with `uv run pytest -m slow`."""

from pathlib import Path
from typing import Any

import pytest
from langchain_core.tools import tool
from langchain_ollama import ChatOllama

from lab.agent.preflight import REASONING_MARKERS, ModelNotReady, check_agent_model
from lab.agent.victim import build_chat_model, open_tools, run_agent, system_prompt
from lab.fixtures.runs import create_run
from promptshield.config import Settings

pytestmark = pytest.mark.slow


@tool
def web_fetch(url: str) -> str:
    """Fetch a web page and return its content."""
    return ""


@tool
def read_file(path: str) -> str:
    """Read a file from the sandbox."""
    return ""


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return ""


def settings(**values: Any) -> Settings:
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


@pytest.fixture
def model() -> Any:
    chat: ChatOllama = build_chat_model(settings())
    return chat.bind_tools([web_fetch, read_file, send_email])


async def test_thinking_is_really_off() -> None:
    await check_agent_model(settings())


async def test_preflight_catches_the_thinking_only_build() -> None:
    """Proves the check works on the model that fooled us, not just on fakes."""
    with pytest.raises(ModelNotReady) as caught:
        await check_agent_model(settings(agent_model="qwen3:4b"))
    if "not available" in str(caught.value):
        pytest.skip("qwen3:4b is not pulled on this machine")
    assert "thinking-only" in str(caught.value)


async def test_picks_web_fetch_with_the_exact_url(model: Any) -> None:
    url = "http://localhost:8081/a02_article.html"
    reply = await model.ainvoke(f"Summarize the article at {url}")
    assert [call["name"] for call in reply.tool_calls] == ["web_fetch"]
    assert reply.tool_calls[0]["args"]["url"] == url


async def test_picks_read_file(model: Any) -> None:
    reply = await model.ainvoke("Read the file notes.md and tell me what it says.")
    assert reply.tool_calls[0]["name"] == "read_file"
    assert reply.tool_calls[0]["args"]["path"] == "notes.md"


async def test_fills_every_email_argument(model: Any) -> None:
    prompt = "Email boss@company.example with the subject 'Q3 report' and the body 'Attached.'"
    reply = await model.ainvoke(prompt)
    args = reply.tool_calls[0]["args"]
    assert args["to"] == "boss@company.example"
    assert args["subject"] == "Q3 report"
    assert "Attached" in args["body"]


async def test_uses_no_tool_when_none_is_needed(model: Any) -> None:
    reply = await model.ainvoke("What is the capital of France? Answer in one word.")
    assert not reply.tool_calls
    assert "paris" in str(reply.content).lower()


async def test_full_agent_run_with_real_tools(tmp_path: Path) -> None:
    run = create_run(tmp_path, "run1", with_attacks=False)
    active = settings()
    async with open_tools(run, ["files"]) as loaded:
        result = await run_agent(
            "Read notes.md and tell me which day the planning meeting is on.",
            build_chat_model(active),
            loaded,
            system_prompt(run),
            max_tool_rounds=active.agent_max_tool_rounds,
        )
    assert result.stopped == "finished"
    assert "read_file" in [step.tool for step in result.steps]
    assert "thursday" in result.final_answer.lower()
    assert not any(marker in result.final_answer.lower()[:40] for marker in REASONING_MARKERS)
