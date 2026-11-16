"""Records what produced a result. Captured when runs happen, not when a report is written."""

import os
import platform
import subprocess

import psutil

from promptshield.config import REPO_ROOT

# Results land here during a run, and they aren't code changes.
EXCLUDED_FROM_DIRTY_CHECK = ":(exclude)eval/reports"


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def git_description() -> str:
    """Return the commit, flagged if the code differs from it. Unknown if git isn't available."""
    try:
        sha = _git("rev-parse", "--short", "HEAD")
        changes = _git("status", "--porcelain", "--", ".", EXCLUDED_FROM_DIRTY_CHECK)
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return f"{sha} (uncommitted changes)" if changes else sha


def machine_description() -> str:
    memory = psutil.virtual_memory().total / 1024**3
    return f"{platform.processor()}, {os.cpu_count()} threads, {memory:.1f} GB RAM, CPU only"
