"""Writes a report for one batch of lab runs. Every number comes from `lab_runs.jsonl`.

uv run python -m eval.report --batch baseline_20261105_2300
"""

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from eval.metrics import Rate, ScenarioResult, Summary, summarize
from promptshield.config import get_settings
from promptshield.models import LabRunOutcome, Schema

RESULTS_FILE = "lab_runs.jsonl"


class RunInfo(Schema):
    batch: str
    date: str
    git: str
    machine: str
    agent_model: str
    num_ctx: int
    think: bool
    repeats: int
    shield: bool = False


def load_batch(results_file: Path, batch: str) -> list[LabRunOutcome]:
    lines = results_file.read_text(encoding="utf-8").splitlines()
    outcomes = [LabRunOutcome.model_validate_json(line) for line in lines if line.strip()]
    return [item for item in outcomes if item.batch == batch]


def run_info(outcomes: Sequence[LabRunOutcome], batch: str) -> RunInfo:
    first = outcomes[0]
    return RunInfo(
        batch=batch,
        date=first.started.strftime("%Y-%m-%d %H:%M UTC"),
        git=first.git,
        machine=first.machine,
        agent_model=first.agent_model,
        num_ctx=first.num_ctx,
        think=first.think,
        repeats=max(item.repeat for item in outcomes) + 1,
        shield=first.shield,
    )


def _scenario_row(item: ScenarioResult) -> str:
    conditions = ", ".join(item.conditions) or "-"
    return (
        f"| {item.scenario_id} | {item.category} | {item.attack_rate.percent()} | "
        f"{item.unknown} | {item.utility.percent()} | {item.median_seconds:.0f} s | {conditions} |"
    )


def _benign_row(item: ScenarioResult) -> str:
    return f"| {item.scenario_id} | {item.utility.percent()} | {item.median_seconds:.0f} s |"


def _category_row(name: str, rate: Rate) -> str:
    return f"| {name} | {rate.percent()} |"


def _failures(summary: Summary) -> list[str]:
    attacks = [item for item in summary.scenarios if item.attack]
    worked = [item.scenario_id for item in attacks if item.attack_rate.hits]
    failed = [
        item.scenario_id for item in attacks if item.attack_rate.total and not item.attack_rate.hits
    ]
    unjudged = [item.scenario_id for item in attacks if not item.attack_rate.total]
    broken = [item.scenario_id for item in summary.scenarios if item.utility.hits == 0]
    return [
        f"- Attacks that worked at least once: {', '.join(worked) or 'none'}",
        f"- Attacks that never worked: {', '.join(failed) or 'none'}",
        f"- Attacks with no judged run: {', '.join(unjudged) or 'none'}",
        f"- Scenarios where the user's task never completed: {', '.join(broken) or 'none'}",
        *([f"- Run problem: {text}" for text in summary.run_problems] or ["- Run problems: none"]),
    ]


def _sample_note(repeats: int) -> str:
    if repeats < 3:
        return (
            f"- {repeats} repeat(s) per scenario. LLM output varies, so a single run shows what "
            "can happen, not how often."
        )
    return f"- {repeats} repeats per scenario is a small sample."


def render_markdown(summary: Summary, info: RunInfo) -> str:
    attacks = [item for item in summary.scenarios if item.attack]
    benign = [item for item in summary.scenarios if not item.attack]
    thinking = "on" if info.think else "off"
    shield = "ON" if info.shield else "OFF"
    setup = "shield on, default policy" if info.shield else "shield off, no policy"
    lines = [
        f"# PromptShield Benchmark: {info.batch}",
        f"Run: {info.date}, git {info.git}, machine {info.machine}, agent {info.agent_model}, "
        f"num_ctx {info.num_ctx}, thinking {thinking}, repeats {info.repeats}, {setup}",
        "",
        "## Headline",
        f"| Metric | Shield {shield} |",
        "|---|---|",
        f"| Attack success rate | {summary.attack_success.percent()} |",
        f"| Utility under attack | {summary.utility_under_attack.percent()} |",
        f"| Benign utility | {summary.utility_benign.percent()} |",
        f"| Runs | {summary.runs} |",
        f"| Attacks with an unknown result | {summary.unknown_attacks} |",
        "",
        "## By attack category",
        "| Category | Attack success |",
        "|---|---|",
        *[_category_row(name, rate) for name, rate in summary.by_category.items()],
        "",
        "## Attack scenarios",
        "| Scenario | Category | Attack success | Unknown | Task done | Median time | Evidence |",
        "|---|---|---|---|---|---|---|",
        *[_scenario_row(item) for item in attacks],
        "",
        "## Benign scenarios",
        "| Scenario | Task done | Median time |",
        "|---|---|---|",
        *[_benign_row(item) for item in benign],
        "",
        "## Latency",
        f"Whole-run time: p50 {summary.p50_seconds:.0f} s, p95 {summary.p95_seconds:.0f} s, "
        f"total {summary.total_minutes:.1f} min. This is agent run time, not shield overhead.",
        "",
        "## Failures",
        *_failures(summary),
        "",
        "## Limitations",
        _sample_note(info.repeats),
        "- A run that crashed or timed out with no evidence of the attack is unknown, and is left "
        "out of attack success. It still counts as a task not done.",
        "- These numbers describe one small local model on CPU, and may not carry over to others.",
        "- A07 reads its image through a mock OCR tool, because the agent model is text-only.",
        "- Attack wording was tuned against this agent with no shield, before the shield existed.",
        "- Paraphrased secrets are not detected, so attack success could read slightly low.",
        "",
    ]
    return "\n".join(lines)


def write_report(outcomes: Sequence[LabRunOutcome], info: RunInfo, reports_dir: Path) -> Path:
    summary = summarize(outcomes)
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{info.batch}.md"
    path.write_text(render_markdown(summary, info), encoding="utf-8", newline="\n")
    raw = {
        "info": info.model_dump(),
        "summary": summary.model_dump(),
        "runs": [item.model_dump(mode="json") for item in outcomes],
    }
    path.with_suffix(".json").write_text(
        json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n"
    )
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a report for one batch of lab runs.")
    parser.add_argument("--batch", required=True)
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    reports_dir = get_settings().reports_dir
    outcomes = load_batch(reports_dir / RESULTS_FILE, args.batch)
    if not outcomes:
        raise SystemExit(f"no runs found for batch {args.batch}")
    info = run_info(outcomes, args.batch)
    print(write_report(outcomes, info, reports_dir))


if __name__ == "__main__":
    main()
