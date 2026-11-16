"""Command line handling for the lab runner."""

import pytest

from lab import run as lab_run
from lab.scenario import load_scenarios
from promptshield.config import Settings


def test_cli_needs_a_target() -> None:
    with pytest.raises(SystemExit):
        lab_run.parse_args([])


@pytest.mark.parametrize(
    "argv",
    [["--all", "--repeats", "0"], ["--all", "--scenario", "A01"], ["--all", "--shield", "maybe"]],
)
def test_cli_refuses_bad_options(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        lab_run.parse_args(argv)


def test_unknown_scenario_is_refused() -> None:
    scenarios = load_scenarios(Settings(_env_file=None))  # type: ignore[call-arg]
    args = lab_run.parse_args(["--scenario", "A99"])
    with pytest.raises(SystemExit, match="A99"):
        lab_run.select(scenarios, args)


def test_scenarios_can_be_selected_in_order() -> None:
    scenarios = load_scenarios(Settings(_env_file=None))  # type: ignore[call-arg]
    args = lab_run.parse_args(["--scenario", "B05", "--scenario", "A02"])
    assert [item.id for item in lab_run.select(scenarios, args)] == ["B05", "A02"]


def test_all_selects_every_scenario() -> None:
    scenarios = load_scenarios(Settings(_env_file=None))  # type: ignore[call-arg]
    assert len(lab_run.select(scenarios, lab_run.parse_args(["--all"]))) == 21


def test_root_cause_unwraps_nested_groups() -> None:
    nested = ExceptionGroup("a", [ExceptionGroup("b", [ValueError("real")])])
    assert isinstance(lab_run._root_cause(nested), ValueError)
