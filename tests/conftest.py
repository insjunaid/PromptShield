"""Shared pytest fixtures."""

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def no_built_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A local `scripts/build_dashboard.py` run puts a build in promptshield/web, which the API
    would then serve on every unknown path. Tests must behave the same with or without it;
    test_web.py mounts its own build explicitly."""
    monkeypatch.setattr("promptshield.api.server.dashboard_built", lambda: False)
