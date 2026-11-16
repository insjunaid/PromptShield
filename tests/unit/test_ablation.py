"""The layer ablation's configs, per-scenario counting, report and the env override."""

import json
import sys
from pathlib import Path

import pytest

from eval import ablation
from eval.lab_suite import run_batch
from tests.unit.test_lab_suite import outcome


def test_one_config_per_layer_plus_the_full_shield() -> None:
    configs = ablation.configs()
    assert [config.name for config in configs] == [
        "full",
        "no-L0",
        "no-L2",
        "no-L1",
        "no-CANARY",
        "no-L3",
        "no-L4",
        "no-REGISTRY",
    ]
    no_l4 = configs[6]
    assert "L4" not in no_l4.layers and len(no_l4.layers) == len(ablation.ALL_LAYERS) - 1
    assert json.loads(no_l4.env()["PROMPTSHIELD_ENABLED_LAYERS"]) == no_l4.layers


def test_a_subset_of_configs_and_unknown_names() -> None:
    assert [c.name for c in ablation.configs(["no-L1", "full"])] == ["full", "no-L1"]
    with pytest.raises(ValueError, match="no-L9"):
        ablation.configs(["no-L9"])


def test_labels_say_which_layer_is_off_and_mark_smoke_runs() -> None:
    full, no_l0 = ablation.configs(["full", "no-L0"])
    assert full.label(3, smoke=False) == "abl3full"
    assert no_l0.label(1, smoke=True) == "abl1smokenoL0"


def test_the_env_override_reaches_the_runner_process() -> None:
    code = (
        "import os; print('batch abl_x shield on'); "
        "print(os.environ['PROMPTSHIELD_ENABLED_LAYERS'])"
    )
    lines: list[str] = []
    env = {"PROMPTSHIELD_ENABLED_LAYERS": '["L0"]'}
    run_batch("on", 1, "abl", lines.append, command=[sys.executable, "-c", code], env=env)
    assert lines[-1] == '["L0"]'


def test_successes_count_only_judged_runs_per_scenario() -> None:
    runs = [
        outcome("A01", attack=True, shield=True, succeeded=True, repeat=0),
        outcome("A01", attack=True, shield=True, succeeded=False, repeat=1),
        outcome("A01", attack=True, shield=True, succeeded=None, repeat=2),
        outcome("A02", attack=True, shield=True, succeeded=False),
    ]
    assert ablation.successes(runs, ["A01", "A02", "A10"]) == {
        "A01": "1/2",
        "A02": "0/1",
        "A10": "0/0",
    }


def test_a_row_keeps_only_the_chosen_scenarios() -> None:
    runs = [
        outcome("A01", attack=True, shield=False, succeeded=True, git="abc"),
        outcome("A05", attack=True, shield=False, succeeded=False, git="abc"),
        outcome("B01", attack=False, shield=False, git="abc"),
    ]
    row = ablation.row("shield-off", None, "lab3off_x", runs, ["A01"])
    assert row.summary.runs == 1 and row.summary.attack_success.percent().startswith("100%")
    with pytest.raises(ValueError, match="no runs"):
        ablation.row("full", None, "b", runs, ["A99"])


def report() -> ablation.AblationReport:
    scenarios = ["A01", "A10"]
    off = [
        outcome("A01", attack=True, shield=False, succeeded=True),
        outcome("A10", attack=True, shield=False, succeeded=True, category="tool_poisoning"),
    ]
    full = [
        outcome("A01", attack=True, shield=True, succeeded=False),
        outcome("A10", attack=True, shield=True, succeeded=False, category="tool_poisoning"),
    ]
    no_registry = [
        outcome("A01", attack=True, shield=True, succeeded=False),
        outcome("A10", attack=True, shield=True, succeeded=True, category="tool_poisoning"),
    ]
    return ablation.AblationReport(
        stamp="20261115_0100",
        machine="test machine",
        power="on mains power",
        agent_model="qwen3:4b-instruct",
        judge_model="qwen3:4b-instruct",
        classifier_threshold=0.10,
        policy="57debaf1c2c1",
        repeats=1,
        scenarios=scenarios,
        reference_off=ablation.row("shield-off", None, "lab3off_x", off, scenarios),
        rows=[
            ablation.row("full", None, "abl1full_x", full, scenarios),
            ablation.row("no-REGISTRY", "REGISTRY", "abl1noREGISTRY_x", no_registry, scenarios),
        ],
        scan=[],
        scan_skipped="turned off with --no-scan",
    )


def test_the_report_shows_each_config_and_where_numbers_came_from() -> None:
    text = ablation.markdown(report(), "chart.png")
    assert "| no-REGISTRY | tool-definition guard (poisoning, rug pulls) | 50%" in text
    assert "| A10 | 1/1 | 0/1 | 1/1 |" in text
    assert "`lab3off_x`" in text and "`abl1noREGISTRY_x`" in text
    assert "Not run: turned off with --no-scan." in text
    assert "in-sample" in text


def test_writing_makes_markdown_json_and_a_chart(tmp_path: Path) -> None:
    path = ablation.write(report(), tmp_path)
    assert path.name == "ablation_20261115_0100.md"
    assert (tmp_path / "ablation_20261115_0100.png").stat().st_size > 0
    data = json.loads((tmp_path / "ablation_20261115_0100.json").read_text(encoding="utf-8"))
    assert [row["name"] for row in data["rows"]] == ["full", "no-REGISTRY"]
