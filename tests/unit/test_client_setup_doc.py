"""The README's install section must match the code, so it breaks a test instead of going stale."""

import json
import re
import shlex
import tomllib

import yaml

from promptshield import cli
from promptshield.config import REPO_ROOT
from promptshield.gateway.server import TASK_HEADER
from promptshield.policy.schema import ToolPolicy

README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
# The "Install" section, up to the next top-level heading.
GUIDE = README.split("## 🚀 Install", 1)[1].split("\n## ", 1)[0]
PYPROJECT = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def blocks(language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", GUIDE, re.DOTALL)


def test_the_json_snippet_is_what_promptshield_config_prints() -> None:
    [block] = blocks("json")
    printed = cli.client_snippet("cursor").split("\n", 1)[1]
    assert json.loads(block) == json.loads(printed)


def test_the_codex_snippet_is_what_promptshield_config_prints() -> None:
    [block] = blocks("toml")
    assert tomllib.loads(block) == tomllib.loads(cli.client_snippet("codex"))


def test_every_app_in_the_table_has_a_config_name() -> None:
    names = re.findall(r"\| `([a-z-]+)` \|$", GUIDE, re.MULTILINE)
    assert len(names) >= 7 and set(names) <= set(cli.CLIENTS)


def test_the_commands_shown_exist() -> None:
    scripts = PYPROJECT["project"]["scripts"]
    assert scripts[cli.PACKAGE] == "promptshield.cli:main"  # `uvx promptshield-mcp` runs it
    for line in blocks("bash"):
        for command in line.splitlines():
            parts = shlex.split(command.split("#", 1)[0])
            if not parts or parts[0] != "uvx":
                continue
            args = parts[1:]
            if args[0] == "--from":
                assert args[1].split("[")[0] == cli.PACKAGE and args[2] == "promptshield"
                args = args[3:]
            else:
                assert args[0] == cli.PACKAGE
                args = args[1:]
            cli.parser().parse_args(args)  # raises SystemExit for an unknown command or flag


def test_the_claude_code_line_names_this_marketplace() -> None:
    assert "/plugin install promptshield --marketplace insjunaid/PromptShield" in GUIDE


def test_the_policy_example_is_valid() -> None:
    [block] = blocks("yaml")
    for entry in yaml.safe_load(block)["tools"].values():
        ToolPolicy.model_validate(entry)


def test_the_bridge_accepts_the_task_flag_the_guide_mentions() -> None:
    assert '"--task"' in GUIDE
    args = cli.parser().parse_args(["bridge", "--task", "Summarize my inbox"])
    assert args.task == "Summarize my inbox"


def test_the_url_and_header_match_the_gateway() -> None:
    assert "http://127.0.0.1:8000/mcp/" in GUIDE
    assert TASK_HEADER.lower() == "x-promptshield-task"
    assert "X-PromptShield-Task" in GUIDE


def test_the_guide_says_real_configs_are_not_touched() -> None:
    assert "never edits your" in GUIDE and "configuration" in GUIDE


def test_the_python_example_uses_the_real_api() -> None:
    from promptshield.sdk import LocalShield, guard_tools

    [block] = blocks("python")
    assert "from promptshield.sdk import LocalShield, guard_tools" in block
    assert callable(guard_tools) and hasattr(LocalShield, "create")
