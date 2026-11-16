"""Logs must stay off stdout, which a stdio MCP gateway uses for the protocol."""

import json
from collections.abc import Iterator

import pytest
import structlog

from promptshield.logs import configure_logging


@pytest.fixture(autouse=True)
def reset_structlog() -> Iterator[None]:
    yield
    structlog.reset_defaults()


def test_json_logs_go_to_stderr_only(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("json")
    structlog.get_logger().warning("something_happened", layer="L1")
    captured = capsys.readouterr()
    assert captured.out == ""
    entry = json.loads(captured.err)
    assert entry["event"] == "something_happened"
    assert entry["layer"] == "L1"
    assert entry["level"] == "warning"


def test_dev_logs_are_readable(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("dev")
    structlog.get_logger().info("started")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "started" in captured.err
