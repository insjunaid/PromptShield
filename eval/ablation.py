"""Layer ablation (P7.3): the lab with each layer turned off in turn, plus a detection-only pass.

Each config is a shield-on lab batch whose process gets `PROMPTSHIELD_ENABLED_LAYERS` without one
layer. Only the attacks that ever succeed against the bare agent are run by default: an attack
that fails with every layer off can't show what one layer adds. Benign tasks aren't rerun either,
because turning a layer off can only remove blocks (P7.2: 0 benign blocked with every layer on).
The shield-off reference is an earlier batch, filtered to the same scenarios.
"""

import json
from collections.abc import Sequence
from pathlib import Path

from eval.metrics import Rate, Summary, summarize
from eval.scan_metrics import DetectionStats
from eval.scan_report import INK, MUTED, SERIES, _style
from promptshield.models import LabRunOutcome, LayerName, Schema

ALL_LAYERS: tuple[LayerName, ...] = ("L0", "L2", "L1", "CANARY", "L3", "L4", "REGISTRY")
# The attacks that succeeded at least once with the shield off in P7.2 (lab3off_20261114_1642).
DEFAULT_SCENARIOS = ("A01", "A02", "A04", "A07", "A10", "A11", "A13")
# Detection-only pass: the content layers that run without the agent or Ollama.
SCAN_LAYERS: tuple[LayerName, ...] = ("L0", "L2", "L1", "CANARY")

LAYER_ROLE: dict[str, str] = {
    # L0 also builds the segments every content layer reads, so turning it off turns off all
    # content detection: what's left is containment (L4, REGISTRY).
    "L0": "normalization, and so all content detection (L0 builds the text the others read)",
    "L1": "classifier (Prompt Guard 2 86M)",
    "L2": "hidden-content and instruction rules",
    "L3": "LLM judge",
    "CANARY": "canary tokens in content",
    "L4": "action guard (egress, taint, DLP, canaries in calls, approvals)",
    "REGISTRY": "tool-definition guard (poisoning, rug pulls)",
}


class AblationConfig(Schema):
    name: str  # "full" or "no-<layer>"
    off: LayerName | None  # the layer turned off, None for the full shield
    layers: list[LayerName]

    def env(self) -> dict[str, str]:
        return {"PROMPTSHIELD_ENABLED_LAYERS": json.dumps(self.layers)}

    def label(self, repeats: int, smoke: bool) -> str:
        """Batch label: `abl3noL4`. A subset run says `smoke`, so it can't pass for a full one."""
        tag = "full" if self.off is None else f"no{self.off}"
        return f"abl{repeats}{'smoke' if smoke else ''}{tag}"


def configs(only: Sequence[str] = ()) -> list[AblationConfig]:
    """The full shield, then one config per layer turned off."""
    out = [AblationConfig(name="full", off=None, layers=list(ALL_LAYERS))]
    out += [
        AblationConfig(
            name=f"no-{layer}", off=layer, layers=[name for name in ALL_LAYERS if name != layer]
        )
        for layer in ALL_LAYERS
    ]
    if only:
        unknown = sorted(set(only) - {config.name for config in out})
        if unknown:
            raise ValueError(f"unknown ablation configs: {unknown}")
        out = [config for config in out if config.name in only]
    return out


class ConfigRow(Schema):
    name: str
    off: str | None
    batch: str
    git: str
    summary: Summary
    successes: dict[str, str]  # scenario -> "hits/judged"


class ScanRow(Schema):
    name: str
    off: str | None
    by_dataset: dict[str, DetectionStats]


class AblationReport(Schema):
    stamp: str
    machine: str
    power: str
    agent_model: str
    judge_model: str
    classifier_threshold: float
    policy: str
    repeats: int
    scenarios: list[str]
    reference_off: ConfigRow | None
    rows: list[ConfigRow]
    scan: list[ScanRow]
    scan_skipped: str | None = None


def successes(runs: Sequence[LabRunOutcome], scenarios: Sequence[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for scenario in scenarios:
        judged = [
            run for run in runs if run.scenario_id == scenario and run.attack_result is not None
        ]
        out[scenario] = f"{sum(bool(run.attack_result) for run in judged)}/{len(judged)}"
    return out


def row(
    name: str,
    off: str | None,
    batch: str,
    runs: Sequence[LabRunOutcome],
    scenarios: Sequence[str],
) -> ConfigRow:
    picked = [run for run in runs if run.scenario_id in scenarios]
    if not picked:
        raise ValueError(f"batch {batch} has no runs for {list(scenarios)}")
    return ConfigRow(
        name=name,
        off=off,
        batch=batch,
        git=picked[0].git,
        summary=summarize(picked),
        successes=successes(picked, scenarios),
    )


def _pct(rate: Rate) -> str:
    return rate.percent()


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def lab_table(report: AblationReport) -> list[str]:
    lines = [
        "| Config | Layer turned off | Attack success | Task completed under attack "
        "| No verdict | Batch |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    rows = ([report.reference_off] if report.reference_off else []) + report.rows
    for item in rows:
        role = LAYER_ROLE.get(item.off or "", "none" if item.name == "full" else "every layer")
        lines.append(
            f"| {item.name} | {role} | {_pct(item.summary.attack_success)} "
            f"| {_pct(item.summary.utility_under_attack)} | {item.summary.unknown_attacks} "
            f"| `{item.batch}` |"
        )
    return lines


def scenario_table(report: AblationReport) -> list[str]:
    rows = ([report.reference_off] if report.reference_off else []) + report.rows
    lines = [
        "| Scenario | " + " | ".join(item.name for item in rows) + " |",
        "| --- |" + " --- |" * len(rows),
    ]
    for scenario in report.scenarios:
        cells = [item.successes.get(scenario, "n/a") for item in rows]
        lines.append(f"| {scenario} | " + " | ".join(cells) + " |")
    return lines


def scan_table(report: AblationReport) -> list[str]:
    datasets = sorted({name for item in report.scan for name in item.by_dataset})
    lines = ["| Config | " + " | ".join(f"{name} recall / benign blocked" for name in datasets)]
    lines[0] += " |"
    lines.append("| --- |" + " --- |" * len(datasets))
    for item in report.scan:
        cells = []
        for name in datasets:
            stats = item.by_dataset.get(name)
            cells.append(
                "n/a" if stats is None else f"{_ratio(stats.recall)} / {_ratio(stats.block_fpr)}"
            )
        lines.append(f"| {item.name} | " + " | ".join(cells) + " |")
    return lines


def markdown(report: AblationReport, chart: str | None) -> str:
    r = report
    lines = [
        "# PromptShield Benchmark: layer ablation",
        "",
        f"Run: {r.stamp}, machine {r.machine}, {r.power}.",
        f"Agent {r.agent_model}, judge {r.judge_model}, L1 threshold {r.classifier_threshold:.2f}, "
        f"policy sha256 {r.policy}, repeats: {r.repeats}.",
        f"Scenarios: {', '.join(r.scenarios)}: the attacks that succeeded at least once with the "
        "shield off. Attacks that fail with every layer off can't show what one layer adds, and",
        "turning a layer off can only remove blocks, so benign tasks weren't rerun (P7.2: 0 benign",
        "blocked with every layer on). Calls that needed approval were denied.",
        "",
        "## Lab: attack success with one layer turned off",
        *lab_table(r),
    ]
    if chart:
        lines += ["", f"![Attack success with each layer turned off]({chart})"]
    lines += [
        "",
        "## Lab: successes per scenario (successful runs / judged runs)",
        *scenario_table(r),
        "",
        "## Detection only: the content layers on the scan datasets",
    ]
    if r.scan:
        lines += [
            "Each item through `/v1/scan` without the agent; judge off; flagged means the decision",
            "isn't ALLOW. Turning a layer off here can only lower recall and benign blocks.",
            "",
            *scan_table(r),
        ]
    else:
        lines.append(f"Not run: {r.scan_skipped or 'not asked for'}.")
    lines += [
        "",
        "## How to read this",
        "- A layer matters for a scenario if turning it off lets that attack succeed again. When",
        "  several layers each stop the same attack, turning one off shows nothing: that is",
        "  defense in depth, not a useless layer.",
        f"- {r.repeats} repeat(s): one run moves a scenario by {100 / r.repeats:.0f} points.",
        "- no-L0 isn't a single-layer test: L0 builds the text L2, L1, CANARY and L3 read, so",
        "  that row shows containment (L4 and REGISTRY) on its own.",
        "- The policy and rules were developed on these scenarios, so this is in-sample.",
        "- With CANARY off, canaries in outgoing calls are still caught by L4; CANARY covers",
        "  canaries in content coming back from tools.",
        "",
    ]
    return "\n".join(lines)


def chart(report: AblationReport, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = ([report.reference_off] if report.reference_off else []) + report.rows
    names = [item.name for item in rows]
    values = [(item.summary.attack_success.value or 0.0) * 100 for item in rows]
    colours = [
        SERIES[0] if item.name == "shield-off" else SERIES[1] if item.name == "full" else SERIES[2]
        for item in rows
    ]
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(names) + 1.4), dpi=150)
    bars = ax.barh(range(len(names)), values, color=colours, height=0.6)
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
    ax.set_xlabel("attack success, % (the attacks that land without the shield)", color=MUTED)
    ax.set_title("Attack success with each layer turned off", color=INK, fontsize=11, loc="left")
    _style(ax)
    ax.grid(axis="x", color="#e3e6eb", linewidth=0.8)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)


def write(report: AblationReport, folder: Path) -> Path:
    base = f"ablation_{report.stamp}"
    chart(report, folder / f"{base}.png")
    (folder / f"{base}.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    path = folder / f"{base}.md"
    path.write_text(markdown(report, f"{base}.png"), encoding="utf-8")
    return path
