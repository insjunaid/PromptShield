"""The one-command demo really starts every service, answers on every URL, and stops cleanly."""

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]
PORTS = (8000, 8081, 9999, 5173)


def busy(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def command() -> list[str]:
    if sys.platform == "win32":
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "scripts" / "demo.ps1"),
            "-Check",
        ]
    return ["bash", str(ROOT / "scripts" / "demo.sh"), "--check"]


def test_the_demo_starts_everything_then_stops_what_it_started() -> None:
    if any(busy(port) for port in PORTS):
        pytest.skip("a demo port is in use; stop the running services first")
    if shutil.which("pnpm") is None or not (ROOT / "dashboard" / "node_modules").exists():
        pytest.skip("dashboard dependencies aren't installed")
    result = subprocess.run(
        command(), cwd=ROOT, capture_output=True, text=True, timeout=300, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Check passed" in result.stdout
    assert "http://127.0.0.1:5173/lab" in result.stdout
    deadline = time.monotonic() + 15
    while any(busy(port) for port in PORTS) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not any(busy(port) for port in PORTS), "a service was left running"
