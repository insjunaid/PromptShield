"""The dashboard served by the API (installed package): pages, files, and the admin cookie."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from promptshield.api.auth import COOKIE_NAME
from promptshield.api.server import create_app
from promptshield.api.web import dashboard_built, mount_dashboard
from promptshield.config import PACKAGE_DIR, Settings
from promptshield.pipeline import LayerRegistry

BASE_URL = "http://127.0.0.1:8000"
ADMIN = "web-test-token"
ORIGIN = {"Origin": BASE_URL}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    # A real build may sit in promptshield/web; this test mounts its own instead.
    monkeypatch.setattr("promptshield.api.server.dashboard_built", lambda: False)
    web = tmp_path / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text("<html>dashboard</html>", encoding="utf-8")
    (web / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside the build", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text((PACKAGE_DIR / "policy" / "default.yaml").read_text("utf-8"), "utf-8")
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        db_path=tmp_path / "web.db",
        models_dir=tmp_path / "no-models",
        admin_token=ADMIN,
        policy_path=policy,
    )
    app = create_app(settings, LayerRegistry())
    mount_dashboard(app, web)
    with TestClient(app, base_url=BASE_URL) as test_client:
        yield test_client


def test_pages_get_the_app_and_an_httponly_strict_cookie(client: TestClient) -> None:
    for path in ("/", "/lab", "/sessions/abc"):
        response = client.get(path)
        assert response.status_code == 200 and "dashboard" in response.text
    cookie = response.headers["set-cookie"].lower()
    assert f"{COOKIE_NAME}={ADMIN}".lower() in cookie
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_built_files_are_served_and_nothing_outside_the_build(client: TestClient) -> None:
    assert client.get("/assets/app.js").text == "console.log(1)"
    escaped = client.get("/../secret.txt")
    assert "outside the build" not in escaped.text


def test_api_paths_are_never_the_dashboard(client: TestClient) -> None:
    assert client.get("/v1/does-not-exist").status_code == 404
    assert client.get("/health").json()["status"] == "ok"


def test_the_cookie_authorizes_the_dashboards_own_requests(client: TestClient) -> None:
    client.get("/")  # sets the cookie
    response = client.post("/v1/policy/mode", json={"mode": "monitor"}, headers=ORIGIN)
    assert response.status_code == 200


def test_the_cookie_does_nothing_for_another_site(client: TestClient) -> None:
    client.get("/")
    evil = {"Origin": "https://evil.example"}
    response = client.post("/v1/policy/mode", json={"mode": "monitor"}, headers=evil)
    assert response.status_code == 401


def test_without_the_cookie_or_header_changes_are_refused(client: TestClient) -> None:
    response = client.post("/v1/policy/mode", json={"mode": "monitor"}, headers=ORIGIN)
    assert response.status_code == 401


def test_the_live_stream_accepts_the_dashboard_served_from_the_api(client: TestClient) -> None:
    url = "ws://127.0.0.1:8000/v1/stream"  # a full URL: a bare path would use host "testserver"
    with client.websocket_connect(url, headers=ORIGIN):
        pass  # accepted: a refused origin raises WebSocketDisconnect on connect
    with (
        pytest.raises(WebSocketDisconnect),  # another site is still refused
        client.websocket_connect(url, headers={"Origin": "https://evil.example"}),
    ):
        pass


def test_a_clone_without_a_build_keeps_the_dev_setup(tmp_path: Path) -> None:
    assert dashboard_built(tmp_path) is False
