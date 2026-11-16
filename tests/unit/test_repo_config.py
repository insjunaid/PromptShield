"""Guards the repo rules that protect secrets and keep lab files trackable."""

import re
import subprocess
import sys
from pathlib import Path

import pytest


def is_git_ignored(repo_root: Path, path: str) -> bool:
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", path], cwd=repo_root, check=False
    )
    return result.returncode == 0


def test_runs_on_python_312() -> None:
    assert sys.version_info[:2] == (3, 12)


def test_slow_and_e2e_markers_are_registered(pytestconfig: pytest.Config) -> None:
    names = {marker.split(":")[0] for marker in pytestconfig.getini("markers")}
    assert {"slow", "e2e"} <= names


@pytest.mark.parametrize(
    "path",
    [".env", "lab/runs/run1/sandbox/.env", "lab/runs/run1/outbox.json", "graft/INDEX.md"],
)
def test_private_and_generated_files_are_ignored(repo_root: Path, path: str) -> None:
    assert is_git_ignored(repo_root, path)


@pytest.mark.parametrize(
    "path", [".env.example", "lab/fixtures/.env", "README.md", "docs/screenshots/hero.gif"]
)
def test_project_files_are_not_ignored(repo_root: Path, path: str) -> None:
    assert not is_git_ignored(repo_root, path)


@pytest.mark.parametrize(
    "path",
    [
        "CLAUDE.md",
        "START_HERE.md",
        ".claude/commands/next.md",
        "docs/PROGRESS.md",
        "docs/ROADMAP.md",
    ],
)
def test_private_working_notes_stay_out_of_the_repository(repo_root: Path, path: str) -> None:
    assert is_git_ignored(repo_root, path)


def test_env_example_holds_no_token(repo_root: Path) -> None:
    text = (repo_root / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^HF_TOKEN=$", text, re.MULTILINE)
    assert not re.search(r"hf_[A-Za-z0-9]{10,}", text)


def test_no_env_file_is_tracked(repo_root: Path) -> None:
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=repo_root, check=True, capture_output=True, text=True
    ).stdout.splitlines()
    assert not [path for path in tracked if Path(path).name == ".env"]
