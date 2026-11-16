"""API behaviour, using the real app with dummy layers."""

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from promptshield.api.routes import health
from promptshield.api.server import create_app
from promptshield.config import Settings
from promptshield.layers.base import ScanContext
from promptshield.models import (
    Decision,
    Event,
    Finding,
    LabRunOutcome,
    LayerName,
    SessionInfo,
    Severity,
    ToolCall,
    Verdict,
)
from promptshield.pipeline import LayerRegistry
from promptshield.redact import Redactor
from promptshield.storage.db import Database

BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/v1/stream"
DASHBOARD = "http://localhost:5173"
CANARY = "sk-canary-a1b2c3d4e5f6"
FAKE_TOKEN = "hf_fakefakefakefakefakefakefake"


class DummyLayer:
    def __init__(self, name: LayerName, findings: list[Finding] | None = None) -> None:
        self.name = name
        self.findings = findings or []

    async def warmup(self) -> None:
        return None

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        return self.findings


def hit(score: float, evidence: str = "evidence") -> Finding:
    return Finding(
        layer="L1",
        rule_id="L1.test",
        title="Looks like an injection",
        severity=Severity.HIGH,
        score=score,
        evidence=evidence,
        # Hidden, so a strong hit blocks: a lone visible hit is capped at SANITIZE (D047).
        segment_origin="hidden_css",
        latency_ms=1,
    )


def registry_with(*findings: Finding) -> LayerRegistry:
    registry = LayerRegistry()
    layer = DummyLayer("L1", list(findings))
    registry.register("L1", lambda: layer)
    return registry


ClientFactory = Callable[..., TestClient]


@pytest.fixture
def make_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ClientFactory]:
    monkeypatch.delenv("HF_TOKEN", raising=False)

    async def ollama_down(url: str) -> bool:
        return False

    monkeypatch.setattr(health, "ollama_reachable", ollama_down)
    opened: list[TestClient] = []

    def build(registry: LayerRegistry | None = None, **options: Any) -> TestClient:
        # An empty models folder: fast tests must never load a real classifier, whatever
        # has been exported on this machine.
        options.setdefault("models_dir", tmp_path / "no-models")
        options.setdefault("admin_token_path", tmp_path / "admin_token")
        settings = Settings(_env_file=None, db_path=tmp_path / "api.db", **options)  # type: ignore[call-arg]
        client = TestClient(
            create_app(settings, registry), base_url=BASE_URL, raise_server_exceptions=False
        )
        client.__enter__()
        opened.append(client)
        return client

    yield build
    for client in opened:
        client.__exit__(None, None, None)


def scan_body(data: str = "hello", **extra: Any) -> dict[str, Any]:
    return {"items": [{"kind": "text", "data": data, "source": "test"}], **extra}


# Health


def test_health_reports_status_and_models(make_client: ClientFactory) -> None:
    response = make_client(registry_with()).get("/health")
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "ok"
    assert body["layers"]["L1"] == "ready"
    assert body["layers"]["L2"] == "unavailable"
    # Built into the app, not loaded models: ready whenever they're enabled.
    assert body["layers"]["L4"] == "ready"
    assert body["layers"]["REGISTRY"] == "ready"
    assert body["models"]["agent"] == "qwen3:4b-instruct"
    assert body["ollama"] is False


def test_health_never_shows_the_token(
    make_client: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HF_TOKEN", FAKE_TOKEN)
    assert FAKE_TOKEN not in make_client().get("/health").text


async def test_ollama_probe_is_false_when_nothing_is_listening() -> None:
    assert await health.ollama_reachable("http://127.0.0.1:1") is False


# Scanning


def test_scan_without_any_layers_fails_closed(make_client: ClientFactory) -> None:
    body = make_client().post("/v1/scan", json=scan_body()).json()
    assert body["decision"] == Decision.BLOCK
    assert body["layers_run"]["L1"] == "error"


def test_scan_of_clean_content_is_allowed(make_client: ClientFactory) -> None:
    response = make_client(registry_with()).post("/v1/scan", json=scan_body())
    assert response.status_code == 200
    assert response.json()["decision"] == Decision.ALLOW


def test_scan_returns_the_policy_decision_and_reasons(make_client: ClientFactory) -> None:
    body = make_client(registry_with(hit(0.99))).post("/v1/scan", json=scan_body()).json()
    assert body["decision"] == Decision.BLOCK
    assert body["reasons"] == ["Looks like an injection"]


def test_scan_response_is_redacted(make_client: ClientFactory) -> None:
    client = make_client(registry_with(hit(0.99, evidence=CANARY)))
    assert "a1b2c3d4" not in client.post("/v1/scan", json=scan_body()).text


def test_scan_stores_an_event_and_session(tmp_path: Path, make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    client.post("/v1/scan", json=scan_body(session_id="s1", user_task="Summarize"))
    database = Database(tmp_path / "api.db", Redactor())
    [event] = database.list_events(session_id="s1")
    session = database.get_session("s1")
    database.close()
    assert event.type == "verdict"
    assert event.payload == {"sources": ["test"]}
    assert session is not None
    assert session.user_task == "Summarize"


def test_scan_reuses_a_known_session(tmp_path: Path, make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    client.post("/v1/scan", json=scan_body(session_id="s1", user_task="First"))
    client.post("/v1/scan", json=scan_body(session_id="s1", user_task="Second"))
    database = Database(tmp_path / "api.db", Redactor())
    session = database.get_session("s1")
    database.close()
    assert session is not None
    assert session.user_task == "First"


def test_scan_survives_a_storage_failure(
    make_client: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object) -> None:
        raise OSError("disk full")

    client = make_client(registry_with())
    monkeypatch.setattr(Database, "save_session", broken)
    monkeypatch.setattr(Database, "add_event", broken)
    assert client.post("/v1/scan", json=scan_body()).json()["decision"] == Decision.ALLOW


def test_failed_redaction_keeps_the_decision_but_drops_the_content(
    make_client: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Redactor, model: Any) -> Any:
        raise ValueError("cannot scrub")

    client = make_client(registry_with(hit(0.99, evidence=CANARY)))
    monkeypatch.setattr(Redactor, "scrub_model", broken)
    response = client.post("/v1/scan", json=scan_body())
    assert response.json()["decision"] == Decision.BLOCK
    assert "a1b2c3d4" not in response.text


# Errors


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"items": []},
        {"items": [{"kind": "text", "data": "x", "source": "y", "surprise": 1}]},
        {"items": [{"kind": "image", "data": "x", "source": "y"}]},
    ],
)
def test_invalid_scan_requests_use_the_error_format(
    make_client: ClientFactory, body: dict[str, Any]
) -> None:
    response = make_client().post("/v1/scan", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_validation_errors_never_echo_the_input(make_client: ClientFactory) -> None:
    body = {"items": [{"kind": "video", "data": CANARY, "source": "y"}]}
    assert "a1b2c3d4" not in make_client().post("/v1/scan", json=body).text


def test_unknown_routes_use_the_error_format(make_client: ClientFactory) -> None:
    response = make_client().get("/missing")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "http_404"


def test_unexpected_errors_hide_the_details(
    make_client: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client(registry_with())

    def broken(*args: object) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr("promptshield.policy.engine.PolicyEngine.decide_inbound", broken)
    response = client.post("/v1/scan", json=scan_body())
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "a1b2c3d4" not in response.text


# Browser protections


def test_foreign_host_header_is_refused(make_client: ClientFactory) -> None:
    """DNS rebinding: a malicious site pointing its own name at this machine."""
    response = make_client().get("/health", headers={"Host": "evil.example"})
    assert response.status_code == 400


@pytest.mark.parametrize("origin", [DASHBOARD, "http://127.0.0.1:5173"])
def test_dashboard_origins_pass_cors(make_client: ClientFactory, origin: str) -> None:
    response = make_client().get("/health", headers={"Origin": origin})
    assert response.headers["access-control-allow-origin"] == origin


def test_other_origins_get_no_cors_header(make_client: ClientFactory) -> None:
    response = make_client().get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers


# WebSocket


def test_client_receives_an_event_after_a_scan(make_client: ClientFactory) -> None:
    client = make_client(registry_with(hit(0.99)))
    with client.websocket_connect(WS_URL) as websocket:
        verdict = client.post("/v1/scan", json=scan_body(session_id="s1")).json()
        message = websocket.receive_json()
    assert message["type"] == "event"
    assert message["data"]["type"] == "verdict"
    assert message["data"]["session_id"] == "s1"
    assert message["data"]["verdict"]["decision"] == verdict["decision"]


def test_streamed_events_are_redacted(make_client: ClientFactory) -> None:
    client = make_client(registry_with(hit(0.99, evidence=CANARY)))
    with client.websocket_connect(WS_URL) as websocket:
        client.post("/v1/scan", json=scan_body())
        assert "a1b2c3d4" not in str(websocket.receive_json())


def test_streamed_event_is_a_valid_event(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    with client.websocket_connect(WS_URL) as websocket:
        client.post("/v1/scan", json=scan_body())
        assert Event.model_validate(websocket.receive_json()["data"]).type == "verdict"


def test_session_filter_on_the_stream(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    with client.websocket_connect(f"{WS_URL}?session_id=wanted") as websocket:
        client.post("/v1/scan", json=scan_body(session_id="other"))
        client.post("/v1/scan", json=scan_body(session_id="wanted"))
        assert websocket.receive_json()["data"]["session_id"] == "wanted"


def test_subscribe_message_changes_the_filter(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    with client.websocket_connect(f"{WS_URL}?session_id=old") as websocket:
        websocket.send_json({"type": "subscribe", "session_id": "new"})
        websocket.send_json({"type": "ping"})
        assert websocket.receive_json() == {"type": "pong"}
        client.post("/v1/scan", json=scan_body(session_id="old"))
        client.post("/v1/scan", json=scan_body(session_id="new"))
        assert websocket.receive_json()["data"]["session_id"] == "new"


def test_ping_gets_a_pong(make_client: ClientFactory) -> None:
    with make_client().websocket_connect(WS_URL) as websocket:
        websocket.send_json({"type": "ping"})
        assert websocket.receive_json() == {"type": "pong"}


def test_bad_client_messages_do_not_close_the_stream(make_client: ClientFactory) -> None:
    with make_client().websocket_connect(WS_URL) as websocket:
        websocket.send_text("not json")
        websocket.send_text("[1, 2]")
        websocket.send_json({"type": "ping"})
        assert websocket.receive_json() == {"type": "pong"}


@pytest.mark.parametrize("origin", [DASHBOARD, "http://127.0.0.1:5173"])
def test_dashboard_origin_can_connect(make_client: ClientFactory, origin: str) -> None:
    with make_client().websocket_connect(WS_URL, headers={"Origin": origin}) as websocket:
        websocket.send_json({"type": "ping"})
        assert websocket.receive_json() == {"type": "pong"}


def test_foreign_origin_cannot_connect(make_client: ClientFactory) -> None:
    client = make_client()
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect(WS_URL, headers={"Origin": "http://evil.example"}),
    ):
        pass


def test_disconnected_clients_are_unsubscribed(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    with client.websocket_connect(WS_URL) as websocket:
        websocket.send_json({"type": "ping"})
        websocket.receive_json()
    assert client.post("/v1/scan", json=scan_body()).status_code == 200
    assert not client.app.state.shield.bus._subscribers  # type: ignore[attr-defined]


# Action guard


def tool_call_body(**args: Any) -> dict[str, Any]:
    return {"session_id": "s-guard", "server": "http", "tool": "http_post", "args": args}


def test_guard_route_blocks_the_control_plane(make_client: ClientFactory) -> None:
    body = tool_call_body(url="http://localhost:8000/v1/policy", data="x")
    response = make_client(registry_with()).post("/v1/guard/tool-call", json=body)
    assert response.status_code == 200
    assert response.json()["decision"] == Decision.BLOCK


def test_guard_route_allows_a_read(make_client: ClientFactory) -> None:
    body = {"session_id": "s-guard", "server": "files", "tool": "read_file", "args": {"path": "x"}}
    response = make_client(registry_with()).post("/v1/guard/tool-call", json=body)
    assert response.json()["decision"] == Decision.ALLOW


def test_guard_route_rejects_a_malformed_call(make_client: ClientFactory) -> None:
    response = make_client(registry_with()).post("/v1/guard/tool-call", json={"tool": "x"})
    assert response.status_code == 422


def test_guard_route_keeps_secrets_out_of_the_event_log(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    client.post("/v1/guard/tool-call", json=tool_call_body(url="http://example.org", key=CANARY))
    database = client.app.state.shield.database  # type: ignore[attr-defined]
    stored = " ".join(str(event.payload) for event in database.list_events(session_id="s-guard"))
    assert stored  # the call was recorded
    assert "a1b2c3d4" not in stored


# Approvals and the admin token

ADMIN = "test-admin-token"


def admin_client(make_client: ClientFactory) -> TestClient:
    return make_client(registry_with(), admin_token=ADMIN)


def start_approval(client: TestClient) -> str:
    """Queues one call inside the app's own event loop, as the gateway will, and returns its id."""
    state = client.app.state.shield  # type: ignore[attr-defined]
    call = ToolCall(session_id="s-ap", server="http", tool="http_post", args={"url": "http://x"})
    verdict = Verdict(decision=Decision.REQUIRE_APPROVAL, risk_score=0.5, reasons=["unknown"])
    client.portal.start_task_soon(state.approvals.request, call, verdict)  # type: ignore[union-attr]
    for _ in range(300):
        pending = state.database.list_approvals(status="pending")
        if pending:
            return str(pending[0].id)
        time.sleep(0.01)
    raise AssertionError("no pending approval appeared")


def test_pending_approvals_can_be_listed_without_a_token(make_client: ClientFactory) -> None:
    client = admin_client(make_client)
    response = client.get("/v1/approvals", params={"status": "pending"})
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize("headers", [{}, {"X-Admin-Token": "wrong"}, {"X-Admin-Token": ""}])
def test_deciding_needs_the_admin_token(
    make_client: ClientFactory, headers: dict[str, str]
) -> None:
    client = admin_client(make_client)
    approval_id = start_approval(client)
    response = client.post(
        f"/v1/approvals/{approval_id}", json={"decision": "approve"}, headers=headers
    )
    assert response.status_code == 401
    state = client.app.state.shield  # type: ignore[attr-defined]
    assert state.database.get_approval(approval_id).status == "pending"
    # Release the waiting call, or shutting the client down waits out the full timeout.
    client.post(
        f"/v1/approvals/{approval_id}", json={"decision": "deny"}, headers={"X-Admin-Token": ADMIN}
    )


def test_an_approval_can_be_decided_with_the_token(make_client: ClientFactory) -> None:
    client = admin_client(make_client)
    approval_id = start_approval(client)
    response = client.post(
        f"/v1/approvals/{approval_id}", json={"decision": "deny"}, headers={"X-Admin-Token": ADMIN}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "denied"
    again = client.post(
        f"/v1/approvals/{approval_id}",
        json={"decision": "approve"},
        headers={"X-Admin-Token": ADMIN},
    )
    assert again.status_code == 409


def test_an_unknown_approval_is_not_found(make_client: ClientFactory) -> None:
    response = admin_client(make_client).post(
        "/v1/approvals/nope", json={"decision": "approve"}, headers={"X-Admin-Token": ADMIN}
    )
    assert response.status_code == 404


def test_a_bad_decision_is_rejected(make_client: ClientFactory) -> None:
    response = admin_client(make_client).post(
        "/v1/approvals/x", json={"decision": "maybe"}, headers={"X-Admin-Token": ADMIN}
    )
    assert response.status_code in (401, 422)


def test_a_fresh_token_is_written_to_a_file_and_never_logged(
    make_client: ClientFactory, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client = make_client(registry_with())
    token = (tmp_path / "admin_token").read_text(encoding="utf-8")
    assert len(token) >= 40
    assert token not in capsys.readouterr().err
    state = client.app.state.shield  # type: ignore[attr-defined]
    assert state.admin_token.get_secret_value() == token


def test_cors_allows_the_admin_token_header(make_client: ClientFactory) -> None:
    response = admin_client(make_client).options(
        "/v1/approvals/x",
        headers={
            "Origin": DASHBOARD,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Admin-Token,Content-Type",
        },
    )
    assert response.status_code == 200
    assert "x-admin-token" in response.headers["access-control-allow-headers"].lower()


# Registry


def test_registry_lists_reviewed_tools(make_client: ClientFactory) -> None:
    response = admin_client(make_client).get("/v1/registry/tools")
    assert response.status_code == 200
    assert response.json() == []  # no upstreams configured in these tests


def test_approving_a_tool_needs_the_admin_token(make_client: ClientFactory) -> None:
    client = admin_client(make_client)
    assert client.post("/v1/registry/tools/evil/get_weather/approve").status_code == 401
    unknown = client.post(
        "/v1/registry/tools/evil/get_weather/approve", headers={"X-Admin-Token": ADMIN}
    )
    assert unknown.status_code == 404


# Red-Team Lab


class FakeRunner:
    """Finishes at once with a canned outcome, or waits until released."""

    def __init__(self, shield: bool, gate: asyncio.Event | None = None) -> None:
        self.shield = shield
        self.gate = gate

    async def run(self, scenario: Any, **kwargs: Any) -> LabRunOutcome:
        if self.gate is not None:
            await self.gate.wait()
        return LabRunOutcome(
            run_id=kwargs["run_id"],
            session_id=kwargs["session_id"],
            batch=kwargs.get("batch", ""),
            scenario_id=scenario.id,
            attack=scenario.attack,
            shield=self.shield,
            status="finished",
            agent_model="test",
            num_ctx=8192,
            think=False,
        )


@asynccontextmanager
async def no_services(settings: Settings) -> AsyncIterator[None]:
    yield


async def empty_sink(settings: Settings) -> list[dict[str, Any]]:
    """No network: on Windows a refused connection takes about 2 s, longer than these tests wait."""
    return []


def lab_client(make_client: ClientFactory, gate: "asyncio.Event | None" = None) -> TestClient:
    from lab.jobs import LabJobs
    from promptshield.sdk import LocalShield

    client = admin_client(make_client)
    state = client.app.state.shield  # type: ignore[attr-defined]
    client.app.state.lab_jobs = LabJobs(  # type: ignore[attr-defined]
        state.settings,
        LocalShield(state),
        runner_factory=lambda shield, auto: FakeRunner(shield, gate),  # type: ignore[arg-type,return-value]
        services=no_services,
        sink=empty_sink,
    )
    return client


def wait_for(client: TestClient, run_id: str, status: str) -> dict[str, Any]:
    for _ in range(300):
        body: dict[str, Any] = client.get(f"/v1/lab/runs/{run_id}").json()
        if body.get("status") == status:
            return body
        time.sleep(0.01)
    raise AssertionError(f"run never reached {status}")


AUTH = {"X-Admin-Token": ADMIN}


def test_lab_lists_the_scenarios(make_client: ClientFactory) -> None:
    ids = {item["id"] for item in lab_client(make_client).get("/v1/lab/scenarios").json()}
    assert {"A02", "A10", "B05"} <= ids


def test_starting_a_run_needs_the_admin_token(make_client: ClientFactory) -> None:
    body = {"scenario_id": "A02", "shield": True}
    assert lab_client(make_client).post("/v1/lab/run", json=body).status_code == 401


def test_an_unknown_scenario_is_not_found(make_client: ClientFactory) -> None:
    body = {"scenario_id": "Z99", "shield": True}
    assert lab_client(make_client).post("/v1/lab/run", json=body, headers=AUTH).status_code == 404


def test_a_run_finishes_and_reports_its_outcome(make_client: ClientFactory) -> None:
    client = lab_client(make_client)
    started = client.post(
        "/v1/lab/run", json={"scenario_id": "A02", "shield": True}, headers=AUTH
    ).json()
    body = wait_for(client, started["run_id"], "finished")
    assert body["outcome"]["shield"] is True
    assert body["session_id"] == started["session_id"]


def test_a_pair_runs_without_then_with_the_shield(make_client: ClientFactory) -> None:
    client = lab_client(make_client)
    runs = client.post("/v1/lab/run-pair", json={"scenario_id": "A02"}, headers=AUTH).json()
    shields = [wait_for(client, run["run_id"], "finished")["shield"] for run in runs]
    assert shields == [False, True]


def test_an_unknown_run_is_not_found(make_client: ClientFactory) -> None:
    assert lab_client(make_client).get("/v1/lab/runs/nope").status_code == 404


def test_reset_needs_the_token_and_waits_for_runs(make_client: ClientFactory) -> None:
    gate_holder: list[asyncio.Event] = []
    client = admin_client(make_client)
    state = client.app.state.shield  # type: ignore[attr-defined]
    gate_holder.append(client.portal.call(asyncio.Event))  # type: ignore[union-attr]
    from lab.jobs import LabJobs
    from promptshield.sdk import LocalShield

    client.app.state.lab_jobs = LabJobs(  # type: ignore[attr-defined]
        state.settings,
        LocalShield(state),
        runner_factory=lambda shield, auto: FakeRunner(shield, gate_holder[0]),  # type: ignore[arg-type,return-value]
        services=no_services,
        sink=empty_sink,
    )
    assert client.post("/v1/lab/reset").status_code == 401
    started = client.post(
        "/v1/lab/run", json={"scenario_id": "A02", "shield": False}, headers=AUTH
    ).json()
    assert client.post("/v1/lab/reset", headers=AUTH).status_code == 409
    client.portal.call(gate_holder[0].set)  # type: ignore[union-attr]
    wait_for(client, started["run_id"], "finished")
    assert client.post("/v1/lab/reset", headers=AUTH).status_code == 200


def test_the_sink_view_needs_the_sink(make_client: ClientFactory) -> None:
    client = lab_client(
        make_client,
    )
    state = client.app.state.shield  # type: ignore[attr-defined]
    state.settings = state.settings.model_copy(update={"sink_port": free_port_api()})
    assert client.get("/v1/lab/sink").status_code == 503


def test_the_sink_view_is_redacted(
    make_client: ClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    from promptshield.api.routes import lab as lab_routes

    async def fake_get(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        stolen = [{"path": "/collect", "query": "", "body": f"key={CANARY}"}]
        return httpx.Response(200, json=stolen, request=httpx.Request("GET", url))

    monkeypatch.setattr(lab_routes.httpx.AsyncClient, "get", fake_get)
    response = lab_client(make_client).get("/v1/lab/sink")
    assert response.status_code == 200
    assert "a1b2c3d4" not in response.text


def free_port_api() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# Events


def publish(client: TestClient, session_id: str, count: int) -> list[str]:
    state = client.app.state.shield  # type: ignore[attr-defined]
    ids = []
    for index in range(count):
        event = client.portal.call(  # type: ignore[union-attr]
            state.bus.publish,
            Event(session_id=session_id, type="agent_message", payload={"n": index}),
        )
        ids.append(event.id)
    return ids


def test_events_come_back_newest_first(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    ids = publish(client, "ev-1", 3)
    body = client.get("/v1/events", params={"session_id": "ev-1"}).json()
    assert [event["id"] for event in body] == list(reversed(ids))


def test_after_returns_what_was_missed_newest_first(make_client: ClientFactory) -> None:
    """Newest first like every page (API_SPEC), holding only the events after that id."""
    client = make_client(registry_with())
    ids = publish(client, "ev-2", 4)
    body = client.get("/v1/events", params={"session_id": "ev-2", "after": ids[1]}).json()
    assert [event["id"] for event in body] == list(reversed(ids[2:]))


def test_an_unknown_event_id_is_an_error(make_client: ClientFactory) -> None:
    response = make_client(registry_with()).get("/v1/events", params={"after": "nope"})
    assert response.status_code == 404


def test_the_page_size_is_bounded(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    assert client.get("/v1/events", params={"limit": 0}).status_code == 422
    assert client.get("/v1/events", params={"limit": 501}).status_code == 422


def test_stored_events_are_redacted(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    state = client.app.state.shield  # type: ignore[attr-defined]
    client.portal.call(  # type: ignore[union-attr]
        state.bus.publish, Event(session_id="ev-3", type="agent_message", payload={"t": CANARY})
    )
    assert "a1b2c3d4" not in client.get("/v1/events", params={"session_id": "ev-3"}).text


def test_runtime_config_shows_the_mode_and_no_secrets(make_client: ClientFactory) -> None:
    response = make_client(registry_with(), admin_token=ADMIN).get("/v1/config")
    body = response.json()
    assert response.status_code == 200
    assert body["mode"] == "enforce"
    assert body["block_threshold"] > body["sanitize_threshold"]
    assert ADMIN not in response.text
    assert FAKE_TOKEN not in response.text


def test_stats_route_answers_for_each_window(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    for window in ("1h", "24h", "all"):
        body = client.get("/v1/stats", params={"window": window}).json()
        assert body["window"] == window
        assert len(body["series"]) == 12
    assert client.get("/v1/stats", params={"window": "week"}).status_code == 422


def test_a_run_reports_only_what_the_sink_received_during_it(make_client: ClientFactory) -> None:
    """Runs go one at a time, so captures made during a run belong to it. Older ones don't."""
    from lab.jobs import LabJobs
    from promptshield.sdk import LocalShield

    old = {"path": "/collect", "query": "", "body": "from an earlier run"}
    stolen = {"path": "/collect", "query": "", "body": f"key={CANARY}"}
    reads: list[int] = []

    async def sink(settings: Settings) -> list[dict[str, Any]]:
        reads.append(1)
        return [old] if len(reads) == 1 else [old, stolen]

    client = admin_client(make_client)
    state = client.app.state.shield  # type: ignore[attr-defined]
    client.app.state.lab_jobs = LabJobs(  # type: ignore[attr-defined]
        state.settings,
        LocalShield(state),
        runner_factory=lambda shield, auto: FakeRunner(shield),  # type: ignore[arg-type,return-value]
        services=no_services,
        sink=sink,
    )
    started = client.post(
        "/v1/lab/run", json={"scenario_id": "A02", "shield": False}, headers=AUTH
    ).json()
    body = wait_for(client, started["run_id"], "finished")
    assert len(body["captured"]) == 1
    assert "from an earlier run" not in str(body["captured"])
    assert "a1b2c3d4" not in str(body)  # the stolen canary is redacted
    assert body["outcome"]["batch"] == "dashboard"  # kept apart from benchmark batches


# Sessions and Attack Replay


def test_sessions_are_listed_newest_first_with_their_counts(make_client: ClientFactory) -> None:
    client = make_client(registry_with(hit(0.99)))
    client.post("/v1/scan", json=scan_body(session_id="s1", user_task="Summarize"))
    client.post("/v1/scan", json=scan_body(session_id="s1"))
    client.post("/v1/scan", json=scan_body(session_id="s2"))
    listed = client.get("/v1/sessions").json()
    assert [item["id"] for item in listed[:2]] == ["s2", "s1"]
    first = client.get("/v1/sessions/s1").json()
    assert first["user_task"] == "Summarize"
    assert first["events"] == 2
    assert first["findings"] == 2
    assert first["max_severity"] == "HIGH"
    assert first["decisions"] == {"BLOCK": 2}
    assert first["lab_run"] is None


def test_replay_is_oldest_first_with_findings_and_redacted(make_client: ClientFactory) -> None:
    client = make_client(registry_with(hit(0.99, evidence=CANARY)))
    for text in ("first", "second"):
        client.post("/v1/scan", json=scan_body(text, session_id="s1"))
    response = client.get("/v1/sessions/s1/replay")
    body = response.json()
    ids = [event["id"] for event in body["events"]]
    assert ids == sorted(ids)
    assert body["truncated"] is False
    assert body["events"][0]["verdict"]["findings"][0]["rule_id"] == "L1.test"
    assert "segments" in body["events"][0]["verdict"]
    assert "a1b2c3d4" not in response.text


def test_a_lab_session_carries_its_outcome(tmp_path: Path, make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    database = Database(tmp_path / "api.db", Redactor())
    database.save_session(SessionInfo(id="lab1", run_id="run1", shield=False, user_task="Read it"))
    database.save_lab_run(
        LabRunOutcome(
            run_id="run1",
            session_id="lab1",
            scenario_id="A02",
            attack=True,
            shield=False,
            status="finished",
            attack_succeeded=True,
            conditions_met=["sink_received_canary"],
            agent_model="test",
            num_ctx=8192,
            think=False,
        )
    )
    database.close()
    body = client.get("/v1/sessions/lab1").json()
    assert body["shield"] is False
    assert body["lab_run"]["scenario_id"] == "A02"
    assert body["lab_run"]["attack_succeeded"] is True


def test_an_unknown_session_is_not_found(make_client: ClientFactory) -> None:
    client = make_client(registry_with())
    assert client.get("/v1/sessions/nope").status_code == 404
    assert client.get("/v1/sessions/nope/replay").status_code == 404


# Policy (P6.6)

POLICY_SOURCE = Path("promptshield/policy/default.yaml")


def policy_client(tmp_path: Path, make_client: ClientFactory) -> tuple[TestClient, Path]:
    """A copy of the real policy, so saves never touch the repository's file."""
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
    return make_client(registry_with(), admin_token=ADMIN, policy_path=path), path


def test_the_policy_comes_back_as_written_and_parsed(
    tmp_path: Path, make_client: ClientFactory
) -> None:
    client, path = policy_client(tmp_path, make_client)
    body = client.get("/v1/policy").json()
    assert body["yaml"] == path.read_text(encoding="utf-8")
    assert "# enforce | monitor" in body["yaml"]  # comments survive
    assert body["policy"]["thresholds"]["block"] == 0.75
    assert body["file"] == "policy.yaml"  # a name, never a path


def test_changing_the_policy_needs_the_token(tmp_path: Path, make_client: ClientFactory) -> None:
    client, path = policy_client(tmp_path, make_client)
    before = path.read_text(encoding="utf-8")
    assert client.put("/v1/policy", json={"yaml": before}).status_code == 401
    assert client.post("/v1/policy/mode", json={"mode": "monitor"}).status_code == 401
    assert path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    ("change", "where"),
    [
        (lambda text: text.replace("block: 0.75", "block: 0.2"), "thresholds"),
        (lambda text: text.replace("mode: enforce", "mode: loud"), "mode"),
        (lambda text: text + "\nweights: [unclosed\n", "line"),
    ],
)
def test_an_invalid_policy_is_refused_and_nothing_changes(
    tmp_path: Path, make_client: ClientFactory, change: Callable[[str], str], where: str
) -> None:
    client, path = policy_client(tmp_path, make_client)
    before = path.read_text(encoding="utf-8")
    response = client.put("/v1/policy", json={"yaml": change(before)}, headers=AUTH)
    assert response.status_code == 422
    assert response.json()["error"]["details"]["problems"][0]["where"].startswith(where)
    assert path.read_text(encoding="utf-8") == before
    assert client.get("/v1/config").json()["block_threshold"] == 0.75


def test_a_saved_policy_is_written_and_live_at_once(
    tmp_path: Path, make_client: ClientFactory
) -> None:
    client, path = policy_client(tmp_path, make_client)
    text = path.read_text(encoding="utf-8").replace("block: 0.75", "block: 0.7  # tighter")
    response = client.put("/v1/policy", json={"yaml": text}, headers=AUTH)
    assert response.status_code == 200
    assert path.read_text(encoding="utf-8") == text
    assert client.get("/v1/config").json()["block_threshold"] == 0.7
    [event] = client.get("/v1/events", params={"type": "policy_changed"}).json()
    assert event["payload"]["block"] == 0.7


def test_switching_mode_keeps_the_rest_of_the_file(
    tmp_path: Path, make_client: ClientFactory
) -> None:
    client, path = policy_client(tmp_path, make_client)
    before = path.read_text(encoding="utf-8")
    response = client.post("/v1/policy/mode", json={"mode": "monitor"}, headers=AUTH)
    assert response.status_code == 200
    after = path.read_text(encoding="utf-8")
    assert after == before.replace("mode: enforce", "mode: monitor", 1)
    assert "# enforce | monitor" in after
    assert client.get("/v1/config").json()["mode"] == "monitor"


# Benchmarks (P6.6)


def bench_client(tmp_path: Path, make_client: ClientFactory) -> TestClient:
    reports = tmp_path / "reports"
    reports.mkdir()
    lab = {
        "info": {
            "batch": "baseline3_x",
            "date": "2026-11-06 17:04 UTC",
            "git": "abc",
            "repeats": 3,
        },
        "summary": {"runs": 2, "by_category": {"hidden_text": {"hits": 1, "total": 2}}},
        "runs": [{"shield": False}, {"shield": False}],
    }
    (reports / "baseline3_x.json").write_text(json.dumps(lab), encoding="utf-8")
    (reports / "judge_check_x.json").write_text(json.dumps({"date": "x", "results": []}), "utf-8")
    (reports / "half_written.json").write_text("{", encoding="utf-8")
    (tmp_path / "secret.json").write_text(json.dumps({"secret": True}), encoding="utf-8")
    return make_client(registry_with(), reports_dir=reports)


def test_reports_are_listed_with_their_kind_and_shield_setting(
    tmp_path: Path, make_client: ClientFactory
) -> None:
    listed = {
        item["id"]: item
        for item in bench_client(tmp_path, make_client).get("/v1/bench/reports").json()
    }
    assert set(listed) == {"baseline3_x", "judge_check_x"}  # the broken file is skipped
    assert listed["baseline3_x"]["kind"] == "lab"
    assert listed["baseline3_x"]["shield"] is False  # taken from the runs: info doesn't say
    assert listed["baseline3_x"]["repeats"] == 3
    assert listed["judge_check_x"]["kind"] == "other"


def test_a_report_is_served_by_id_and_only_from_its_folder(
    tmp_path: Path, make_client: ClientFactory
) -> None:
    client = bench_client(tmp_path, make_client)
    report = client.get("/v1/bench/reports/baseline3_x").json()
    assert report["summary"]["by_category"]["hidden_text"] == {"hits": 1, "total": 2}
    for bad in ("..%2Fsecret", "nope", ".hidden", "half_written"):
        assert client.get(f"/v1/bench/reports/{bad}").status_code == 404


# Approval cards (P6.6)


def test_an_approval_shows_where_the_call_goes(make_client: ClientFactory) -> None:
    client = admin_client(make_client)
    approval_id = start_approval(client)
    [card] = client.get("/v1/approvals", params={"status": "pending"}).json()
    assert card["id"] == approval_id
    assert card["destination"] == "http://x"  # from the policy's arg_destination for http_post
    assert card["user_task"] is None  # this session never said
    client.post(f"/v1/approvals/{approval_id}", json={"decision": "deny"}, headers=AUTH)
