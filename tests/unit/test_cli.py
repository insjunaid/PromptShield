"""The `promptshield` command: app snippets, the server list, and where an install keeps files."""

import json
import tomllib
from pathlib import Path

import pytest

from promptshield import cli
from promptshield.config import HOME_ENV, REPO_ROOT, Settings, default_home, is_source_checkout


def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, servers_file=tmp_path / "servers.json")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "client", ["claude-desktop", "cursor", "windsurf", "gemini", "antigravity"]
)
def test_json_apps_get_an_mcp_servers_entry_that_runs_the_bridge(client: str) -> None:
    text = cli.client_snippet(client)
    body = json.loads(text.split("\n", 1)[1])  # first line names the file
    assert body["mcpServers"]["promptshield"] == {"command": "uvx", "args": [cli.PACKAGE, "bridge"]}


def test_vscode_uses_its_own_servers_key() -> None:
    body = json.loads(cli.client_snippet("vscode").split("\n", 1)[1])
    assert body["servers"]["promptshield"]["type"] == "stdio"


def test_codex_gets_valid_toml() -> None:
    body = tomllib.loads(cli.client_snippet("codex"))
    assert body["mcp_servers"]["promptshield"] == {
        "command": "uvx",
        "args": [cli.PACKAGE, "bridge"],
    }


def test_claude_code_gets_one_command() -> None:
    assert (
        cli.client_snippet("claude-code")
        == f"claude mcp add promptshield -- uvx {cli.PACKAGE} bridge"
    )


def test_every_listed_app_has_a_snippet() -> None:
    for client in cli.CLIENTS:
        assert cli.client_snippet(client)


def test_servers_are_added_replaced_and_removed(tmp_path: Path) -> None:
    config = settings(tmp_path)
    cli.add_server(config, "files", ["npx", "-y", "server-filesystem", "/docs"])
    cli.add_server(config, "files", ["npx", "-y", "server-filesystem", "/other"])
    cli.add_server(config, "web", ["uvx", "mcp-server-fetch"])
    names = [(s.name, s.args[-1]) for s in cli.read_servers(config)]
    assert names == [("files", "/other"), ("web", "mcp-server-fetch")]
    assert cli.remove_server(config, "web") is True
    assert cli.remove_server(config, "web") is False
    assert [s.name for s in cli.read_servers(config)] == ["files"]


def test_a_server_needs_a_valid_name_and_a_command(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli.add_server(settings(tmp_path), "files", [])
    with pytest.raises(ValueError, match="pattern"):
        cli.add_server(settings(tmp_path), "Bad Name", ["npx"])


def test_the_command_line_strips_the_separator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, list[str]] = {}
    monkeypatch.setattr(cli, "cmd_servers", lambda args: seen.update(cmd=args.server_command))
    cli.main(["servers", "add", "files", "--", "npx", "-y", "pkg"])
    assert seen["cmd"] == ["npx", "-y", "pkg"]


def test_the_shield_reads_the_server_list(tmp_path: Path) -> None:
    config = settings(tmp_path)
    cli.add_server(config, "files", ["npx", "-y", "pkg"])
    assert [s.name for s in settings(tmp_path).gateway_upstreams] == ["files"]


def test_servers_set_in_the_environment_win(tmp_path: Path) -> None:
    config = settings(tmp_path)
    cli.add_server(config, "files", ["npx"])
    env = Settings(  # type: ignore[call-arg]
        _env_file=None,
        servers_file=tmp_path / "servers.json",
        gateway_upstreams=[{"name": "web", "command": "uvx"}],
    )
    assert [s.name for s in env.gateway_upstreams] == ["web"]


def test_a_clone_is_its_own_home_and_an_install_uses_the_user_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert is_source_checkout(REPO_ROOT)
    assert not is_source_checkout(tmp_path)
    monkeypatch.setenv(HOME_ENV, str(tmp_path / "custom"))
    assert default_home() == (tmp_path / "custom").resolve()
    monkeypatch.delenv(HOME_ENV)
    assert default_home() == REPO_ROOT


def test_the_default_policy_ships_inside_the_package() -> None:
    path = Settings(_env_file=None).policy_path  # type: ignore[call-arg]
    assert path.is_file() and path.parent.parent.name == "promptshield"
