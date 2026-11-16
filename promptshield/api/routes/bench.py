"""Benchmark reports from eval/reports, served as written. The dashboard shows where each came from.

Lab reports (`eval.report`) have `info` and `summary`; other checks (judge, phase 3) are listed as
"other" so nothing in the folder is hidden.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException

from promptshield.api.state import AppState, get_state
from promptshield.models import Schema

router = APIRouter()

# A report id is a file stem. Nothing else is accepted, so an id can never leave the folder.
REPORT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")

State = Annotated[AppState, Depends(get_state)]


class ReportSummary(Schema):
    id: str
    kind: Literal["lab", "other"]
    date: str | None = None
    git: str | None = None
    shield: bool | None = None  # lab reports only
    repeats: int | None = None
    runs: int | None = None
    modified: float  # file time, for sorting and provenance


def _shield(report: dict[str, Any]) -> bool | None:
    """Older reports don't record it in `info`, but every run does."""
    info = report.get("info", {})
    if isinstance(info.get("shield"), bool):
        return bool(info["shield"])
    settings = {run.get("shield") for run in report.get("runs", []) if isinstance(run, dict)}
    if len(settings) != 1:
        return None  # no runs, or a mix
    value = next(iter(settings))
    return value if isinstance(value, bool) else None


def _summarize(path: Path) -> ReportSummary | None:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None  # unreadable or half-written: skip it rather than fail the list
    if not isinstance(report, dict):
        return None
    modified = path.stat().st_mtime
    info = report.get("info")
    if isinstance(info, dict) and isinstance(report.get("summary"), dict):
        return ReportSummary(
            id=path.stem,
            kind="lab",
            date=info.get("date"),
            git=info.get("git"),
            shield=_shield(report),
            repeats=info.get("repeats"),
            runs=report["summary"].get("runs"),
            modified=modified,
        )
    return ReportSummary(
        id=path.stem,
        kind="other",
        date=str(report.get("date")) if report.get("date") else None,
        git=report.get("git"),
        modified=modified,
    )


def _list(folder: Path) -> list[ReportSummary]:
    if not folder.is_dir():
        return []
    items = [summary for path in folder.glob("*.json") if (summary := _summarize(path))]
    return sorted(items, key=lambda item: item.modified, reverse=True)


@router.get("/v1/bench/reports")
async def list_reports(state: State) -> list[ReportSummary]:
    """Newest first."""
    return await asyncio.to_thread(_list, state.settings.reports_dir)


@router.get("/v1/bench/reports/{report_id}")
async def get_report(report_id: str, state: State) -> dict[str, Any]:
    if not REPORT_ID.fullmatch(report_id):
        raise HTTPException(status_code=404, detail="unknown report")
    path = state.settings.reports_dir / f"{report_id}.json"
    try:
        text = await asyncio.to_thread(path.read_text, encoding="utf-8")
        report: dict[str, Any] = json.loads(text)
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=404, detail="unknown report") from error
    return report
