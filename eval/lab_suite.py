"""The lab suite: every scenario with the shield off, then on, compared in one report.

Each batch runs `lab.run` in its own process, so the shield-off run's memory is gone before the
shield-on run loads its classifier, and each batch still gets the usual per-batch report (which the
dashboard's Benchmarks page reads). This module adds the side-by-side report that
EVALUATION.md §4 asks for.
"""

import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Literal

from eval.metrics import Rate, Summary
from eval.scan_report import INK, MUTED, SERIES, _style
from promptshield.models import LabRunOutcome, Schema

BATCH_LINE = re.compile(r"^batch (\S+) shield (on|off)$")


def parse_batch(line: str) -> str | None:
    """`lab.run` prints `batch <name> shield <on|off>` before its first run."""
    match = BATCH_LINE.match(line.strip())
    return match.group(1) if match else None


def run_batch(
    shield: Literal["on", "off"],
    repeats: int,
    label: str,
    echo: Callable[[str], None] = print,
    scenarios: Sequence[str] = (),
    command: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Run the scenarios (all by default) once per repeat. Returns the batch name. Raises if the
    run fails, so a broken shield-off run never quietly leads into a shield-on one. `env` adds
    settings for that process only (the ablation turns layers off this way)."""
    target = [part for item in scenarios for part in ("--scenario", item)] or ["--all"]
    args = list(command) if command else [sys.executable, "-m", "lab.run", *target]
    args += ["--repeats", str(repeats), "--shield", shield, "--label", label]
    batch: str | None = None
    with subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, **env} if env else None,
    ) as process:
        assert process.stdout is not None
        for line in process.stdout:
            echo(line.rstrip())
            batch = batch or parse_batch(line)
    if process.returncode != 0 or batch is None:
        raise RuntimeError(f"lab.run with the shield {shield} failed (exit {process.returncode})")
    return batch


def policy_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


class BatchRef(Schema):
    batch: str
    shield: bool
    repeats: int
    runs: int
    git: str
    report: str  # the per-batch report's file name


class LabComparison(Schema):
    stamp: str
    machine: str
    power: str
    agent_model: str
    num_ctx: int
    think: bool
    judge_model: str
    classifier_threshold: float
    policy: str  # short sha256 of the policy file
    off: BatchRef
    on: BatchRef
    off_summary: Summary
    on_summary: Summary


def _pct(rate: Rate) -> str:
    return rate.percent()


def headline(comparison: LabComparison) -> list[str]:
    off, on = comparison.off_summary, comparison.on_summary
    rows = [
        "| Metric | Shield OFF | Shield ON |",
        "| --- | --- | --- |",
        f"| Attack success rate (lower is better) | {_pct(off.attack_success)} "
        f"| {_pct(on.attack_success)} |",
        f"| Benign tasks completed | {_pct(off.utility_benign)} | {_pct(on.utility_benign)} |",
        f"| Task completed under attack | {_pct(off.utility_under_attack)} "
        f"| {_pct(on.utility_under_attack)} |",
        f"| Attack runs with no verdict (left out) | {off.unknown_attacks} "
        f"| {on.unknown_attacks} |",
        f"| Run time per scenario, p50 / p95 | {off.p50_seconds:.0f} s / {off.p95_seconds:.0f} s "
        f"| {on.p50_seconds:.0f} s / {on.p95_seconds:.0f} s |",
        f"| Runs | {off.runs} | {on.runs} |",
    ]
    return rows


def by_category(comparison: LabComparison) -> list[str]:
    off, on = comparison.off_summary.by_category, comparison.on_summary.by_category
    rows = ["| Category | Shield OFF | Shield ON |", "| --- | --- | --- |"]
    for name in sorted(set(off) | set(on)):
        before = off[name].percent() if name in off else "n/a"
        after = on[name].percent() if name in on else "n/a"
        rows.append(f"| {name} | {before} | {after} |")
    return rows


def failures(runs: Sequence[LabRunOutcome]) -> list[str]:
    """With the shield on: attacks that got through, and benign tasks that weren't completed."""
    through = [run for run in runs if run.attack and run.attack_succeeded]
    broken = [run for run in runs if not run.attack and run.utility_ok is False]
    lines = [f"- Attacks that got through with the shield on: {len(through)}"]
    lines += [
        f"  - {run.scenario_id} repeat {run.repeat}: {', '.join(run.conditions_met)}; "
        f"blocked_by: {', '.join(run.blocked_by) or 'nothing'}"
        for run in through
    ]
    lines.append(f"- Benign tasks not completed with the shield on: {len(broken)}")
    lines += [
        f"  - {run.scenario_id} repeat {run.repeat}: status {run.status}; "
        f"blocked_by: {', '.join(run.blocked_by) or 'nothing'}"
        for run in broken
    ]
    return lines


def markdown(comparison: LabComparison, on_runs: Sequence[LabRunOutcome], chart: str | None) -> str:
    c = comparison
    lines = [
        "# PromptShield Benchmark: lab suite",
        "",
        f"Run: {c.stamp}, machine {c.machine}, {c.power}.",
        f"Agent {c.agent_model}, judge {c.judge_model}, num_ctx {c.num_ctx}, think {c.think}, "
        f"L1 threshold {c.classifier_threshold:.2f}, policy sha256 {c.policy}.",
        f"Shield OFF: batch `{c.off.batch}` (git {c.off.git}, repeats: {c.off.repeats}, "
        f"report {c.off.report}).",
        f"Shield ON: batch `{c.on.batch}` (git {c.on.git}, repeats: {c.on.repeats}, "
        f"report {c.on.report}).",
        "Calls that needed approval were denied, as the policy's timeout would.",
        "",
        "Attack success is judged from the environment after each run (the attacker sink, the",
        "outbox, the files), not from what the agent says. Runs with no verdict are counted on",
        "their own, not as blocked.",
        "",
        "## Headline",
        *headline(c),
        "",
        "## By attack category (attack success)",
        *by_category(c),
    ]
    if chart:
        lines += ["", f"![Attack success by category, shield off vs on]({chart})"]
    lines += [
        "",
        "## Failures (shield on)",
        *failures(on_runs),
        "",
        "## Limitations",
        "- A small local model as the agent: a stronger agent may follow attacks more or less",
        "  often.",
        "- Few runs per scenario (LLMs vary even at temperature 0): one run moves a scenario by a",
        "  third at 3 repeats.",
        "- Approvals were always denied; a human approving some calls would trade safety for",
        "  utility.",
        "- A07's image text comes from a mock OCR tool in the lab.",
        "- Detectors can be evaded by adaptive attackers; defense-in-depth reduces, not",
        "  eliminates, risk.",
        "- Run time is the whole agent run on this laptop's CPU, not the shield's added latency",
        "  (P7.4 measures that).",
        "",
    ]
    return "\n".join(lines)


def category_chart(comparison: LabComparison, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    off, on = comparison.off_summary.by_category, comparison.on_summary.by_category
    names = sorted(set(off) | set(on))

    def share(rates: dict[str, Rate], name: str) -> float:
        value = rates[name].value if name in rates else None
        return 0.0 if value is None else value * 100

    fig, ax = plt.subplots(figsize=(8, 0.5 * len(names) + 1.4), dpi=150)
    height = 0.36
    for offset, rates, colour, label in (
        (-height / 2, off, SERIES[0], "Shield OFF"),
        (height / 2, on, SERIES[1], "Shield ON"),
    ):
        values = [share(rates, name) for name in names]
        bars = ax.barh(
            [index + offset for index in range(len(names))],
            values,
            height=height - 0.04,
            color=colour,
            label=label,
        )
        for bar, value in zip(bars, values, strict=True):
            ax.annotate(
                f"{value:.0f}%",
                (bar.get_width(), bar.get_y() + bar.get_height() / 2),
                xytext=(4, 0),
                textcoords="offset points",
                va="center",
                color=INK,
                fontsize=8,
            )
    ax.set_yticks(range(len(names)), names, color=INK, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 110)
    ax.set_xlabel("attack success, %", color=MUTED)
    ax.set_title("Attack success by category", color=INK, fontsize=11, loc="left")
    legend = ax.legend(frameon=False, fontsize=8, loc="lower right")
    for text in legend.get_texts():
        text.set_color(MUTED)
    _style(ax)
    ax.grid(axis="x", color="#e3e6eb", linewidth=0.8)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)


def write(comparison: LabComparison, on_runs: Sequence[LabRunOutcome], folder: Path) -> Path:
    base = f"lab_{comparison.stamp}"
    category_chart(comparison, folder / f"{base}_categories.png")
    (folder / f"{base}.json").write_text(comparison.model_dump_json(indent=2), encoding="utf-8")
    path = folder / f"{base}.md"
    path.write_text(markdown(comparison, on_runs, f"{base}_categories.png"), encoding="utf-8")
    return path
