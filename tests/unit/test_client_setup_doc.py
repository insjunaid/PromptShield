"""The README's client setup section must match the code, so it breaks a test instead of going
stale."""

import importlib.util
import json
import re

import pytest
import yaml

from promptshield.config import REPO_ROOT, Settings
from promptshield.gateway import stdio_bridge
from promptshield.gateway.server import TASK_HEADER
from promptshield.policy.schema import ToolPolicy

README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
# The "Use it with your own MCP client" section, up to the next heading.
GUIDE = README.split("## 🔌 Use it with your own MCP client", 1)[1].split("\n## ", 1)[0]


def blocks(language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", GUIDE, re.DOTALL)


def env_value(name: str) -> str:
    match = re.search(rf"^{name}=(.+)$", GUIDE, re.MULTILINE)
    assert match, f"{name} is not shown in the guide"
    return match.group(1)


def test_every_json_snippet_parses() -> None:
    assert blocks("json")
    for block in blocks("json"):
        json.loads(block)


def test_the_upstream_example_loads_into_real_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "PROMPTSHIELD_GATEWAY_UPSTREAMS", env_value("PROMPTSHIELD_GATEWAY_UPSTREAMS")
    )
    [upstream] = Settings(_env_file=None).gateway_upstreams  # type: ignore[call-arg]
    assert upstream.name == "files"


def test_the_policy_example_is_valid() -> None:
    [block] = blocks("yaml")
    for entry in yaml.safe_load(block)["tools"].values():
        ToolPolicy.model_validate(entry)


def test_the_bridge_command_names_a_real_module() -> None:
    config = json.loads(blocks("json")[0])
    args = config["mcpServers"]["promptshield"]["args"]
    module = args[args.index("-m") + 1]
    assert importlib.util.find_spec(module) is not None
    assert module == stdio_bridge.__name__


def test_the_bridge_accepts_the_flags_the_guide_mentions() -> None:
    assert '"--task"' in GUIDE
    args = stdio_bridge.parse_args(["--task", "Summarize my inbox"])
    assert args.task == "Summarize my inbox"
    assert stdio_bridge.parse_args([]).url == "http://127.0.0.1:8000/mcp/"


def test_the_url_and_header_match_the_gateway() -> None:
    assert "http://127.0.0.1:8000/mcp/" in GUIDE
    assert TASK_HEADER.lower() == "x-promptshield-task"
    assert "X-PromptShield-Task" in GUIDE


def test_the_guide_says_real_configs_are_not_touched() -> None:
    assert "never edits your client's configuration" in GUIDE
