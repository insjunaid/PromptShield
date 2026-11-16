"""The README's links resolve, its numbers come from the reports it cites, and the honesty checklist
and license notices stay in place."""

import re
import subprocess
from pathlib import Path

import pytest

from promptshield.config import Settings

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text("utf-8")
REPORTS = ROOT / "eval" / "reports"


def local_links(text: str) -> set[str]:
    targets = re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'src="([^"]+)"', text)
    return {t.split("#")[0] for t in targets if not t.startswith(("http", "#", "mailto:"))}


def test_every_local_link_and_image_exists() -> None:
    missing = sorted(link for link in local_links(README) if not (ROOT / link).exists())
    assert missing == []


def test_no_link_points_at_a_file_that_is_not_published() -> None:
    """Working notes (docs/*.md, CLAUDE.md) are git-ignored: a link to one would break on GitHub."""
    # No trailing slash: on a CRLF checkout, `check-ignore` treats a blank .gitignore line as a
    # pattern that matches any path ending in "/", though real ignoring is unaffected.
    links = sorted(link.rstrip("/") for link in local_links(README))
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", *links],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.stdout.split() == []


@pytest.mark.parametrize(
    ("report", "numbers"),
    [
        (
            "lab_20261114_1826.md",
            ["37% (15/41)", "0% (0/42)", "100% (21/21)", "95% (40/42)", "50% (21/42)"],
        ),
        (
            "latency_20261116_1606.md",
            ["| 46 ms | 221 ms |", "| 69 ms | 8.1 s |", "| 10 ms |", "| 37 ms |"],
        ),
        ("scan_20261114_1552.md", ["| 100% | 18% |", "Chosen: **0.10**"]),
    ],
)
def test_headline_numbers_are_in_the_cited_report(report: str, numbers: list[str]) -> None:
    assert f"eval/reports/{report}" in README
    text = (REPORTS / report).read_text("utf-8")
    missing = [number for number in numbers if number not in text]
    assert missing == []


def test_the_honesty_checklist_items_are_stated() -> None:
    lowered = README.lower()
    assert "qwen3:4b-instruct" in README and "num_ctx" in README and "thinking off" in README
    assert "mock ocr" in lowered  # A07 disclosed
    assert "adaptive attacker" in lowered
    assert "in-sample" in lowered and "never used for tuning" in lowered
    assert re.search(r"^## .*limitations$", lowered, re.M)


DISCLAIMER = (
    "PromptShield is a research/portfolio project. The attack lab runs entirely on localhost "
    "against a deliberately vulnerable demo agent. No detector stops 100% of prompt injections; "
    "PromptShield reduces risk through layered defenses. Don't rely on it as your only control "
    "in production."
)


def test_the_disclaimer_is_in_place() -> None:
    assert DISCLAIMER in " ".join(README.split())


def test_license_and_llama_notice_are_present() -> None:
    assert (ROOT / "LICENSE").read_text("utf-8").startswith("MIT License")
    notice = (ROOT / "NOTICE").read_text("utf-8")
    assert "Built with Llama" in notice and "Llama 4 Community License" in notice
    assert "Built with Llama" in README


def test_the_example_env_uses_the_measured_models() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    example = (ROOT / ".env.example").read_text("utf-8")
    assert f"PROMPTSHIELD_AGENT_MODEL={settings.agent_model}" in example
    assert f"PROMPTSHIELD_JUDGE_MODEL={settings.judge_model}" in example
