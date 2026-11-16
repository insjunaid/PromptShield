"""Creates the isolated state for one lab run, so paired runs can't affect each other."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from lab.attack_site.payloads import ENV_FILE, SECRET_FILE
from lab.fixtures import content
from lab.fixtures.canaries import CanarySet, generate_canaries

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class RunPaths:
    root: Path

    @property
    def sandbox(self) -> Path:
        return self.root / "sandbox"

    @property
    def inbox(self) -> Path:
        return self.root / "inbox.json"

    @property
    def outbox(self) -> Path:
        return self.root / "outbox.json"

    @property
    def canaries(self) -> Path:
        return self.root / "canaries.json"


def run_paths(runs_dir: Path, run_id: str) -> RunPaths:
    """Validate the id first: it can arrive through the API and becomes a directory name."""
    if not RUN_ID.fullmatch(run_id):
        raise ValueError(f"invalid run id: {run_id!r}")
    return RunPaths(runs_dir / run_id)


def _write_sandbox(paths: RunPaths, canaries: CanarySet, with_attacks: bool) -> None:
    paths.sandbox.mkdir()
    files = {
        content.NOTES_FILE: content.NOTES_TEXT,
        content.REPORT_FILE: content.REPORT_TEXT,
        ENV_FILE: content.env_file_text(canaries),
        SECRET_FILE: content.secrets_file_text(canaries),
    }
    if with_attacks:
        files[content.ATTACK_FILE] = content.ATTACK_FILE_TEXT
    for name, text in files.items():
        (paths.sandbox / name).write_text(text, encoding="utf-8", newline="\n")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def create_run(runs_dir: Path, run_id: str, *, with_attacks: bool) -> RunPaths:
    """Build a fresh run. An existing run is refused, because old state would skew the result.

    `with_attacks` adds the A08 email and A13 file, and must be False for benign scenarios.
    """
    paths = run_paths(runs_dir, run_id)
    paths.root.mkdir(parents=True, exist_ok=False)
    canaries = generate_canaries(run_id)
    _write_sandbox(paths, canaries, with_attacks)
    emails = content.inbox_emails(canaries, with_attacks)
    _write_json(paths.inbox, [email.model_dump() for email in emails])
    _write_json(paths.outbox, [])
    _write_json(paths.canaries, canaries.model_dump())
    return paths


def load_canaries(paths: RunPaths) -> CanarySet:
    return CanarySet.model_validate_json(paths.canaries.read_text(encoding="utf-8"))
