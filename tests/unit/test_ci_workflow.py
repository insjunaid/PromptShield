"""The CI workflow runs what the docs say CI runs, with no secrets and read-only permissions."""

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW: dict[Any, Any] = yaml.safe_load(
    (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
)


def commands(job: str) -> list[str]:
    return [step["run"] for step in WORKFLOW["jobs"][job]["steps"] if "run" in step]


def test_python_job_lints_type_checks_and_runs_the_fast_tests() -> None:
    runs = " ".join(commands("python"))
    assert "uv sync --frozen --group eval" in runs  # charts in the eval tests need matplotlib
    assert "ruff check" in runs and "ruff format --check" in runs and "mypy" in runs
    assert 'pytest -q -m "not slow and not e2e"' in runs  # TESTING.md: what CI runs
    assert WORKFLOW["jobs"]["python"]["env"]["HF_HUB_OFFLINE"] == "1"


def test_dashboard_job_tests_and_builds_from_the_lockfile() -> None:
    runs = commands("dashboard")
    assert runs == ["pnpm install --frozen-lockfile", "pnpm test", "pnpm build"]


def test_ci_is_read_only_and_needs_no_secrets() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert "secrets." not in text and "HF_TOKEN" not in text


PUBLISH: dict[Any, Any] = yaml.safe_load(
    (ROOT / ".github" / "workflows" / "publish.yml").read_text("utf-8")
)


def test_publishing_runs_on_a_release_with_trusted_publishing_only() -> None:
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text("utf-8")
    triggers = PUBLISH[True]  # YAML reads the key `on` as True
    assert triggers["release"]["types"] == ["published"]
    assert PUBLISH["permissions"] == {"contents": "read"}
    job = PUBLISH["jobs"]["publish"]
    assert job["permissions"] == {"id-token": "write"}
    assert job["environment"]["name"] == "pypi" and job["if"] == "github.event_name == 'release'"
    assert any("pypa/gh-action-pypi-publish" in step.get("uses", "") for step in job["steps"])
    assert "${{ secrets." not in text  # no stored token or password is used
    for each in PUBLISH["jobs"].values():
        for step in each["steps"]:
            assert "password" not in step.get("with", {})


def test_the_package_is_built_with_its_dashboard_and_checked_before_publishing() -> None:
    runs = [step.get("run", "") for step in PUBLISH["jobs"]["build"]["steps"]]
    order = [
        next(i for i, run in enumerate(runs) if needle in run)
        for needle in (
            "build_dashboard.py",
            "uv build",
            "twine check --strict",
            "dashboard_built()",
        )
    ]
    assert order == sorted(order)


def test_the_plugin_and_the_package_share_one_version() -> None:
    import json
    import tomllib

    version = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["version"]
    plugin = json.loads((ROOT / "plugin" / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    assert plugin["version"] == version


def test_the_python_version_matches_the_project() -> None:
    steps = WORKFLOW["jobs"]["python"]["steps"]
    uv = next(step for step in steps if step.get("uses", "").startswith("astral-sh/setup-uv"))
    assert uv["with"]["python-version"] == "3.12"
    assert 'requires-python = ">=3.12,<3.13"' in (ROOT / "pyproject.toml").read_text("utf-8")
