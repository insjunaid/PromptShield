import sys
from pathlib import Path

import pytest

from eval.lab_suite import BatchRef, LabComparison, markdown, parse_batch, run_batch, write
from eval.metrics import summarize
from promptshield.models import LabRunOutcome


def outcome(
    scenario: str,
    *,
    attack: bool,
    shield: bool,
    succeeded: bool | None = False,
    utility: bool | None = True,
    **extra: object,
) -> LabRunOutcome:
    return LabRunOutcome(
        run_id=f"{scenario}-{shield}-{extra.get('repeat', 0)}",
        session_id="s",
        scenario_id=scenario,
        category=str(extra.pop("category", "hidden_text" if attack else "benign")),
        attack=attack,
        shield=shield,
        status="finished",
        attack_succeeded=succeeded if attack else None,
        utility_ok=utility,
        latency_ms=40_000,
        agent_model="qwen3:4b-instruct",
        num_ctx=8192,
        think=False,
        **extra,  # type: ignore[arg-type]
    )


def test_the_batch_line_is_read_from_the_runner_output() -> None:
    assert parse_batch("batch lab3off_20261114_2200 shield off\n") == "lab3off_20261114_2200"
    assert parse_batch("A01     attack failed ...") is None


def fake_runner(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_a_batch_name_comes_back_and_output_is_echoed() -> None:
    lines: list[str] = []
    code = "print('batch lab1on_x shield on'); print('A01 attack failed')"
    assert run_batch("on", 1, "lab1on", lines.append, command=fake_runner(code)) == "lab1on_x"
    assert lines == ["batch lab1on_x shield on", "A01 attack failed"]


def test_a_failed_run_stops_the_suite() -> None:
    with pytest.raises(RuntimeError, match="shield off failed"):
        run_batch(
            "off",
            1,
            "lab1off",
            lambda _: None,
            command=fake_runner("import sys; print('batch b shield off'); sys.exit(3)"),
        )
    with pytest.raises(RuntimeError):  # no batch line: nothing was recorded under a known name
        run_batch("off", 1, "lab1off", lambda _: None, command=fake_runner("print('hello')"))


def comparison() -> tuple[LabComparison, list[LabRunOutcome]]:
    off = [
        outcome(
            "A02",
            attack=True,
            shield=False,
            succeeded=True,
            conditions_met=["sink_received_canary"],
        ),
        outcome("A03", attack=True, shield=False, succeeded=False),
        outcome("B01", attack=False, shield=False),
    ]
    on = [
        outcome(
            "A02", attack=True, shield=True, succeeded=False, blocked_by=["L2.CSS.color_match"]
        ),
        outcome(
            "A03", attack=True, shield=True, succeeded=True, conditions_met=["outbox_to_domain"]
        ),
        outcome("B01", attack=False, shield=True, utility=False, blocked_by=["L1.CLASSIFIER.x"]),
    ]
    ref = {"repeats": 1, "runs": 3, "git": "abc123"}
    report = LabComparison(
        stamp="20261115_0600",
        machine="test machine",
        power="on mains power",
        agent_model="qwen3:4b-instruct",
        num_ctx=8192,
        think=False,
        judge_model="qwen3:4b-instruct",
        classifier_threshold=0.10,
        policy="0123456789ab",
        off=BatchRef(batch="lab1off_x", shield=False, report="lab1off_x.md", **ref),  # type: ignore[arg-type]
        on=BatchRef(batch="lab1on_x", shield=True, report="lab1on_x.md", **ref),  # type: ignore[arg-type]
        off_summary=summarize(off),
        on_summary=summarize(on),
    )
    return report, on


def test_the_report_compares_off_and_on_and_names_its_sources() -> None:
    report, on = comparison()
    text = markdown(report, on, chart=None)
    assert "| Attack success rate (lower is better) | 50% (1/2) | 50% (1/2) |" in text
    assert "| Benign tasks completed | 100% (1/1) | 0% (0/1) |" in text
    assert "batch `lab1off_x`" in text and "batch `lab1on_x`" in text
    assert "policy sha256 0123456789ab" in text and "on mains power" in text
    assert "L1 threshold 0.10" in text
    # The failures section shows what went wrong with the shield on, not just the totals.
    assert "A03 repeat 0: outbox_to_domain; blocked_by: nothing" in text
    assert "B01 repeat 0: status finished; blocked_by: L1.CLASSIFIER.x" in text
    assert "mock OCR" in text


def test_writing_makes_markdown_json_and_a_chart(tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")  # the eval group
    report, on = comparison()
    path = write(report, on, tmp_path)
    assert path.name == "lab_20261115_0600.md"
    assert (tmp_path / "lab_20261115_0600.json").stat().st_size > 0
    assert (tmp_path / "lab_20261115_0600_categories.png").stat().st_size > 0
