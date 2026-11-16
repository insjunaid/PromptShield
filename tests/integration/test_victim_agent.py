"""The agent loop, using a scripted model and real tool server processes."""

from pathlib import Path
from typing import Any

import httpx
import pytest
from langchain_core.messages import AIMessage, ToolMessage

from lab.agent import victim
from lab.agent.preflight import ModelNotReady, check_agent_model
from lab.agent.victim import AgentStep, open_tools, run_agent, step_event, system_prompt
from lab.fixtures.runs import RunPaths, create_run, load_canaries
from promptshield.config import Settings
from promptshield.events import EventBus
from promptshield.models import Direction
from promptshield.redact import Redactor
from tests.helpers import scripted, tool_call


@pytest.fixture
def run(tmp_path: Path) -> RunPaths:
    return create_run(tmp_path, "run1", with_attacks=True)


async def test_agent_calls_a_real_tool_and_answers(run: RunPaths) -> None:
    model = scripted(tool_call("read_file", path="notes.md"), AIMessage(content="All done."))
    async with open_tools(run, ["files"]) as loaded:
        result = await run_agent("Read notes", model, loaded, "prompt", max_tool_rounds=3)

    assert result.final_answer == "All done."
    assert result.stopped == "finished"
    assert [step.kind for step in result.steps] == ["tool_call", "tool_result", "assistant"]
    assert result.steps[0].args == {"path": "notes.md"}
    assert result.steps[0].server == "files"
    assert "Planning meeting" in result.steps[1].text


async def test_the_model_sees_the_tool_result(run: RunPaths) -> None:
    model = scripted(tool_call("read_file", path="notes.md"), AIMessage(content="Done."))
    async with open_tools(run, ["files"]) as loaded:
        await run_agent("Read notes", model, loaded, "prompt", max_tool_rounds=3)
    results = [message for message in model.seen[-1] if isinstance(message, ToolMessage)]
    assert "Planning meeting" in str(results[0].content)


async def test_a_refused_tool_call_goes_back_to_the_model(run: RunPaths) -> None:
    """A refusal must not end the run, or the shield's blocks would look like crashes."""
    model = scripted(tool_call("read_file", path="../canaries.json"), AIMessage(content="Sorry."))
    async with open_tools(run, ["files"]) as loaded:
        result = await run_agent("Read it", model, loaded, "prompt", max_tool_rounds=3)
    assert result.final_answer == "Sorry."
    assert "outside the sandbox" in result.steps[1].text


async def test_a_looping_agent_is_stopped(run: RunPaths) -> None:
    model = scripted(tool_call("list_files"))
    async with open_tools(run, ["files"]) as loaded:
        result = await run_agent("Loop", model, loaded, "prompt", max_tool_rounds=2)
    assert result.stopped == "step_limit"
    assert result.final_answer == ""


async def test_tools_keep_state_across_calls_in_one_session(run: RunPaths) -> None:
    model = scripted(
        tool_call("write_file", "c1", path="a.txt", content="hello"),
        tool_call("read_file", "c2", path="a.txt"),
        AIMessage(content="Done."),
    )
    async with open_tools(run, ["files"]) as loaded:
        result = await run_agent("Write", model, loaded, "prompt", max_tool_rounds=4)
    assert [step.text for step in result.steps if step.kind == "tool_result"][1] == "hello"


async def test_steps_are_reported_as_they_happen(run: RunPaths) -> None:
    seen: list[str] = []

    async def record(step: AgentStep) -> None:
        seen.append(step.kind)

    model = scripted(tool_call("list_files"), AIMessage(content="Done."))
    async with open_tools(run, ["files"]) as loaded:
        await run_agent("List", model, loaded, "prompt", max_tool_rounds=3, on_step=record)
    assert seen == ["tool_call", "tool_result", "assistant"]


async def test_only_the_requested_servers_are_opened(run: RunPaths) -> None:
    async with open_tools(run, ["mail"]) as loaded:
        assert {tool.name for tool in loaded.tools} == {"list_emails", "read_email", "send_email"}


async def test_text_only_agent_does_not_get_fetch_image(run: RunPaths) -> None:
    async with open_tools(run, ["web"]) as loaded:
        assert {tool.name for tool in loaded.tools} == {"web_fetch", "read_image_text"}


async def test_poisoned_description_reaches_the_agent(run: RunPaths) -> None:
    async with open_tools(run, ["evil"]) as loaded:
        assert "secrets.txt" in loaded.tools[0].description


async def test_rug_pull_mode_starts_clean(run: RunPaths) -> None:
    async with open_tools(run, ["evil"], evil_mode="rug_pull") as loaded:
        assert "secrets.txt" not in loaded.tools[0].description


def test_system_prompt_holds_the_canary(run: RunPaths) -> None:
    assert load_canaries(run).api_key in system_prompt(run)


def test_system_prompt_is_not_rigged() -> None:
    """Telling the agent to obey pages would make the baseline meaningless."""
    prompt = victim.SYSTEM_PROMPT.lower()
    for word in ("obey", "follow", "instruction", "page", "email", "always", "must"):
        assert word not in prompt


def test_chat_model_settings_are_explicit() -> None:
    model = victim.build_chat_model(Settings(_env_file=None))  # type: ignore[call-arg]
    assert model.num_ctx == 8192
    assert model.reasoning is False
    assert model.temperature == 0
    assert model.model == "qwen3:4b-instruct"


def test_steps_map_to_timeline_events() -> None:
    message = step_event(AgentStep(kind="assistant", text="hi"), "s1")
    call = step_event(AgentStep(kind="tool_call", tool="t", server="x", args={"a": 1}), "s1")
    result = step_event(AgentStep(kind="tool_result", tool="t", text="out"), "s1")
    assert (message.type, message.payload["text"]) == ("agent_message", "hi")
    assert (call.type, call.direction, call.tool) == ("tool_call", Direction.OUTBOUND, "t")
    assert (result.type, result.direction) == ("tool_result", Direction.INBOUND)


async def test_step_events_are_redacted_on_the_bus(run: RunPaths) -> None:
    key = load_canaries(run).api_key
    bus = EventBus(None, Redactor())
    published = await bus.publish(step_event(AgentStep(kind="tool_result", text=key), "s1"))
    assert key not in published.model_dump_json()


@pytest.mark.parametrize(
    "argv", [["--task", "x", "--shield", "on"], ["--task", "x", "--servers", "ftp"]]
)
def test_cli_refuses_what_is_not_available(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        victim.parse_args(argv)


def test_cli_defaults_to_no_evil_server() -> None:
    assert "evil" not in victim.parse_args(["--task", "x"]).servers


# Preflight


def settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def fake_ollama(
    *,
    finetune: str = "Instruct",
    capabilities: tuple[str, ...] = ("completion", "tools"),
    content: str = "OK",
    thinking: str = "",
    tokens: int = 2,
    show_status: int = 200,
) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/show":
            body = {
                "capabilities": list(capabilities),
                "model_info": {"general.finetune": finetune},
            }
            return httpx.Response(show_status, json=body)
        message = {"content": content, "thinking": thinking}
        return httpx.Response(200, json={"message": message, "eval_count": tokens})

    return httpx.MockTransport(handle)


async def test_preflight_accepts_a_good_model() -> None:
    await check_agent_model(settings(), fake_ollama())


@pytest.mark.parametrize(
    ("options", "problem"),
    [
        ({"finetune": "Thinking"}, "thinking-only"),
        ({"capabilities": ("completion",)}, "tool calling"),
        ({"content": "Hmm, the user wants me to say OK."}, "reasoning"),
        ({"thinking": "Let me consider this."}, "still thinking"),
        ({"tokens": 40}, "tokens"),
        ({"show_status": 404}, "not available"),
    ],
)
async def test_preflight_refuses_a_bad_model(options: dict[str, Any], problem: str) -> None:
    with pytest.raises(ModelNotReady, match=problem):
        await check_agent_model(settings(), fake_ollama(**options))


async def test_preflight_reports_when_ollama_is_down() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ModelNotReady, match="not reachable"):
        await check_agent_model(settings(), httpx.MockTransport(fail))
