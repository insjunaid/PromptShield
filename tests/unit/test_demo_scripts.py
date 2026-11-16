"""The demo scripts and Makefile stay in step with the configured ports (no services started)."""

import re
from pathlib import Path

from promptshield.config import Settings

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = Settings(_env_file=None)  # type: ignore[call-arg]
PORTS = {
    SETTINGS.api_port,
    SETTINGS.attack_site_port,
    SETTINGS.sink_port,
    SETTINGS.dashboard_port,
}


def ports_in(path: Path) -> set[int]:
    return {int(port) for port in re.findall(r"127\.0\.0\.1:(\d+)", path.read_text("utf-8"))}


def test_both_scripts_use_the_configured_ports_and_only_loopback() -> None:
    for name in ("demo.ps1", "demo.sh"):
        script = ROOT / "scripts" / name
        assert ports_in(script) == PORTS, name
        text = script.read_text("utf-8")
        assert "0.0.0.0" not in text and "localhost:" not in text.replace("localhost:11434", "")


def test_both_scripts_start_the_same_services_and_have_a_check_mode() -> None:
    modules = ("lab.attack_site.serve", "lab.attacker_sink.server", "promptshield.api.server")
    for name, flag in (("demo.ps1", "$Check"), ("demo.sh", "--check")):
        text = (ROOT / "scripts" / name).read_text("utf-8")
        assert all(module in text for module in modules), name
        assert "dashboard" in text and "dev" in text
        assert flag in text


def test_make_has_demo_targets() -> None:
    makefile = (ROOT / "Makefile").read_text("utf-8")
    assert re.search(r"^demo:\n\t\$\(RUN_SCRIPT\) scripts/demo\.\$\(EXT\)$", makefile, re.M)
    assert re.search(r"^demo-check:\n\t.*\$\(CHECK_FLAG\)$", makefile, re.M)
