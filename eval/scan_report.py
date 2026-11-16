"""Write the scan suite's report: JSON (raw), Markdown (read), PNG charts (look).

Chart colours are the dashboard's categorical slots, validated for a white background with the
dataviz palette checker (D065). Aqua is under 3:1 on white, so every line is labelled directly and
the Markdown repeats the numbers as a table.
"""

from pathlib import Path
from typing import Any

from eval.scan_metrics import DetectionStats, ItemResult, SweepPoint
from promptshield.models import Schema

SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]  # categorical slots 1-3, light theme
INK, MUTED, GRID = "#111418", "#5b6472", "#e3e6eb"


class ConfigResult(Schema):
    name: str
    label: str
    models: list[str]
    flag_rule: str  # how "flagged" was decided, said in the report
    by_dataset: dict[str, DetectionStats]
    results: list[ItemResult]


class Calibration(Schema):
    model: str
    dataset: str
    max_fpr: float
    current: float
    chosen: SweepPoint | None
    points: list[SweepPoint]
    test_at_chosen: DetectionStats | None = None  # the chosen threshold on held-out data
    test_at_current: DetectionStats | None = None


class ScanReport(Schema):
    stamp: str
    git: str
    machine: str
    power: str = "not recorded"
    datasets: dict[str, dict[str, int]]  # name -> {"items", "attacks", "benign"}
    configs: list[ConfigResult]
    calibration: Calibration | None = None
    skipped: list[str] = []


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f}"


def _snippet(text: str, limit: int = 110) -> str:
    flat = " ".join(text.split()).replace("|", "/")
    return flat if len(flat) <= limit else f"{flat[: limit - 1]}…"


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


HEADLINE_HEADER = [
    "Config",
    "Precision",
    "Recall",
    "F1",
    "Benign flagged",
    "Benign blocked (FPR)",
    "Benign sanitized",
    "Errors",
    "p50 / p95 ms",
]


def headline_rows(report: ScanReport, dataset: str) -> list[str]:
    rows = [_row(HEADLINE_HEADER), _row(["---"] * len(HEADLINE_HEADER))]
    for config in report.configs:
        stats = config.by_dataset.get(dataset)
        if stats is None:
            continue
        cells = [
            config.label,
            _pct(stats.precision),
            _pct(stats.recall),
            _pct(stats.f1),
            _pct(stats.flagged_benign_rate),
            _pct(stats.block_fpr),
            _pct(stats.sanitized_benign_rate),
            str(stats.errors),
            f"{_ms(stats.p50_ms)} / {_ms(stats.p95_ms)}",
        ]
        rows.append(_row(cells))
    return rows


def failures(
    config: ConfigResult, texts: dict[str, str], flagged: set[str], dataset: str, limit: int = 6
) -> list[str]:
    results = [r for r in config.results if r.dataset == dataset and r.error is None]
    missed = [r for r in results if r.attack and r.id not in flagged]
    false_alarms = [r for r in results if not r.attack and r.id in flagged]
    lines = [
        f"**{config.label}, {dataset}:** {len(missed)} missed attacks, "
        f"{len(false_alarms)} false alarms (up to {limit} of each shown)"
    ]
    lines += [f"- missed `{r.id}`: {_snippet(texts.get(r.id, ''))}" for r in missed[:limit]]
    for r in false_alarms[:limit]:
        how = str(r.decision) if r.decision else f"score {r.l1_score:.2f}"
        lines.append(f"- false alarm `{r.id}` ({how}): {_snippet(texts.get(r.id, ''))}")
    return lines


def calibration_rows(calibration: Calibration) -> list[str]:
    rows = [_row(["Threshold", "Precision", "Recall", "FPR"]), _row(["---"] * 4)]
    chosen = calibration.chosen.threshold if calibration.chosen else None
    for point in calibration.points:
        mark = " ← chosen" if point.threshold == chosen else ""
        mark += " (current)" if point.threshold == calibration.current else ""
        cells = [f"{point.threshold:.2f}{mark}", _pct(point.precision), _pct(point.recall)]
        rows.append(_row([*cells, _pct(point.fpr)]))
    return rows


USES = {
    "deepset-train": "calibration only (L1 threshold)",
    "deepset-test": "held-out reporting: never used for tuning",
    "lab": "development data: these texts shaped earlier tuning (D046-D049)",
}


def _calibration_section(calibration: Calibration, charts: dict[str, str]) -> list[str]:
    lines = [
        "",
        "## Threshold calibration",
        f"{calibration.model} alone, swept on {calibration.dataset}. "
        "Rule (EVALUATION.md §3): the highest recall",
        f"with FPR at most {calibration.max_fpr:.0%}.",
    ]
    point = calibration.chosen
    if point:
        lines.append(
            f"Chosen: **{point.threshold:.2f}** (precision {_pct(point.precision)}, "
            f"recall {_pct(point.recall)}, FPR {_pct(point.fpr)} on calibration data)."
        )
    else:
        lines.append("No threshold kept FPR that low: the configured value stays.")
    for label, stats in (
        ("chosen", calibration.test_at_chosen),
        ("current", calibration.test_at_current),
    ):
        if stats:
            lines.append(
                f"On the held-out test split at the {label} threshold: precision "
                f"{_pct(stats.precision)}, recall {_pct(stats.recall)}, "
                f"FPR {_pct(stats.flagged_benign_rate)}."
            )
    if "calibration" in charts:
        lines += ["", f"![Precision, recall and FPR by L1 threshold]({charts['calibration']})"]
    return [*lines, "", *calibration_rows(calibration)]


def markdown(
    report: ScanReport, texts: dict[str, str], flagged: dict[str, set[str]], charts: dict[str, str]
) -> str:
    lines = [
        "# PromptShield Benchmark: scan suite",
        "",
        f"Run: {report.stamp}, git {report.git}, machine {report.machine}, {report.power}.",
        "Detection only: no agent. Each item is sent alone through the real app's `POST /v1/scan`",
        'with the task "Summarize this for me." Classifiers are fp32 ONNX on CPU.',
        "",
        "## Data",
        _row(["Dataset", "Items", "Attacks", "Benign", "Use"]),
        _row(["---"] * 5),
    ]
    for name, counts in report.datasets.items():
        cells = [name, str(counts["items"]), str(counts["attacks"]), str(counts["benign"])]
        lines.append(_row([*cells, USES.get(name, "")]))
    lines += [
        "",
        "`deepset/prompt-injections` (Apache-2.0) mixes English and German.",
        "Lab pages are whole HTML pages, as `web_fetch` returns them.",
    ]
    for dataset, title in (
        ("deepset-test", "Headline: deepset test split (held out)"),
        ("lab", "Lab set (development data)"),
    ):
        lines += ["", f"## {title}", *headline_rows(report, dataset)]
    lines += [
        "",
        "FPR counts benign items BLOCKED. Sanitized benign items still reach the agent and are",
        "counted on their own. Classifier-alone rows have no policy, so blocking isn't defined",
        "for them. Errors are items where a layer failed and the policy failed closed: they are",
        "left out of the rates rather than counted as catches.",
        'How each row decides "flagged", and which model its rule ids show really ran:',
    ]
    for config in report.configs:
        models = ", ".join(config.models) or "none (no L1)"
        lines.append(f"- {config.label}: flagged when {config.flag_rule}; models: {models}")
    if "configs" in charts:
        lines += ["", f"![Recall and benign flagged rate per config]({charts['configs']})"]
    if report.calibration:
        lines += _calibration_section(report.calibration, charts)
    lines += ["", "## Failures"]
    for config in report.configs:
        for dataset in ("deepset-test", "lab"):
            if dataset in config.by_dataset:
                lines += failures(config, texts, flagged[config.name], dataset)
    if report.skipped:
        lines += ["", "## Not run", *[f"- {item}" for item in report.skipped]]
    lines += [
        "",
        "## Limitations",
        "- Small held-out set (116 items): one item moves a rate by about 2 points.",
        "- Item level, not agent level: whether an attack would have worked is the lab suite's",
        "  job.",
        "- Detectors can be evaded by adaptive attackers; defense-in-depth reduces, not",
        "  eliminates, risk.",
        "- Latency is the shield's own time per item on this laptop's CPU, without the agent.",
        "",
    ]
    return "\n".join(lines)


def _style(ax: Any) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def calibration_chart(calibration: Calibration, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    xs = [point.threshold for point in calibration.points]
    series = [
        ("Precision", [p.precision for p in calibration.points], "-"),
        ("Recall", [p.recall for p in calibration.points], "--"),
        ("FPR", [p.fpr for p in calibration.points], ":"),
    ]
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    ends: list[tuple[str, float, float]] = []
    for (name, values, dash), colour in zip(series, SERIES, strict=True):
        ys = [float("nan") if value is None else value * 100 for value in values]
        ax.plot(xs, ys, dash, color=colour, linewidth=2, marker="o", markersize=4)
        last = next(
            ((x, y) for x, y in zip(reversed(xs), reversed(ys), strict=True) if y == y), None
        )
        if last:
            ends.append((name, *last))
    # Direct labels at the line ends, nudged apart when lines end close together.
    placed: list[float] = []
    for name, x, y in sorted(ends, key=lambda end: -end[2]):
        label_y = y
        while any(abs(label_y - other) < 5 for other in placed):
            label_y -= 5
        placed.append(label_y)
        ax.annotate(  # no arrow, so the anchor is just where the text sits
            name,
            (x, label_y),
            xytext=(8, 0),
            textcoords="offset points",
            va="center",
            color=INK,
            fontsize=9,
            annotation_clip=False,
        )
    ax.axhline(calibration.max_fpr * 100, color=MUTED, linewidth=1, linestyle=(0, (2, 3)))
    ax.annotate(
        f"FPR limit {calibration.max_fpr:.0%}",
        (xs[0], calibration.max_fpr * 100),
        xytext=(0, 4),
        textcoords="offset points",
        color=MUTED,
        fontsize=8,
    )
    for value, label in (
        (calibration.current, "current"),
        (calibration.chosen.threshold if calibration.chosen else None, "chosen"),
    ):
        if value is not None:
            ax.axvline(value, color=MUTED, linewidth=1)
            ax.annotate(
                label, (value, 102), ha="center", color=INK, fontsize=8, annotation_clip=False
            )
    ax.set_xlabel("L1 threshold", color=MUTED)
    ax.set_ylabel("%", color=MUTED)
    ax.set_ylim(0, 100)
    ax.set_xlim(xs[0] - 0.02, xs[-1] + 0.12)
    title = f"{calibration.model} on {calibration.dataset}"
    ax.set_title(title, color=INK, fontsize=11, loc="left", pad=18)  # room for the line labels
    _style(ax)
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)


def configs_chart(report: ScanReport, dataset: str, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = [(c.label, c.by_dataset[dataset]) for c in report.configs if dataset in c.by_dataset]
    labels = [label for label, _ in rows]
    recall = [(stats.recall or 0) * 100 for _, stats in rows]
    flagged = [(stats.flagged_benign_rate or 0) * 100 for _, stats in rows]
    fig, ax = plt.subplots(figsize=(8, 0.6 * len(rows) + 1.4), dpi=150)
    positions = range(len(rows))
    height = 0.36
    for offset, values, colour, name in (
        (-height / 2, recall, SERIES[0], "Recall (attacks caught)"),
        (height / 2, flagged, SERIES[1], "Benign flagged"),
    ):
        bars = ax.barh(
            [p + offset for p in positions], values, height=height - 0.04, color=colour, label=name
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
    ax.set_yticks(list(positions), labels, color=INK, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 110)
    ax.set_xlabel("%", color=MUTED)
    ax.set_title(f"Detection by config, {dataset}", color=INK, fontsize=11, loc="left")
    legend = ax.legend(frameon=False, fontsize=8, loc="lower right")
    for text in legend.get_texts():
        text.set_color(MUTED)
    _style(ax)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)


def write(
    report: ScanReport, texts: dict[str, str], flagged: dict[str, set[str]], folder: Path
) -> Path:
    """Writes scan_<stamp>.json, .md and the PNG charts beside them. Returns the .md path."""
    folder.mkdir(parents=True, exist_ok=True)
    base = f"scan_{report.stamp}"
    charts: dict[str, str] = {}
    if any("deepset-test" in c.by_dataset for c in report.configs):
        configs_chart(report, "deepset-test", folder / f"{base}_configs.png")
        charts["configs"] = f"{base}_configs.png"
    if report.calibration:
        calibration_chart(report.calibration, folder / f"{base}_calibration.png")
        charts["calibration"] = f"{base}_calibration.png"
    (folder / f"{base}.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    path = folder / f"{base}.md"
    path.write_text(markdown(report, texts, flagged, charts), encoding="utf-8")
    return path
