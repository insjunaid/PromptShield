"""Builds the dashboard and copies it into the package, so `promptshield start` can serve it.

    uv run python scripts/build_dashboard.py      # then: uv build

The output (promptshield/web/) is git-ignored and goes into the wheel through hatch's `artifacts`.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "dashboard"
TARGET = ROOT / "promptshield" / "web"


def main() -> None:
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise SystemExit("pnpm is needed to build the dashboard")
    subprocess.run([pnpm, "install", "--frozen-lockfile"], cwd=DASHBOARD, check=True)  # noqa: S603
    subprocess.run([pnpm, "build"], cwd=DASHBOARD, check=True)  # noqa: S603
    shutil.rmtree(TARGET, ignore_errors=True)
    shutil.copytree(DASHBOARD / "dist", TARGET)
    files = sum(1 for path in TARGET.rglob("*") if path.is_file())
    print(f"copied {files} files to {TARGET.relative_to(ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
