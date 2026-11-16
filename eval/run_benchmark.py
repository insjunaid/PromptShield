"""Benchmark runner: the scan suite (detection only) and the lab suite (agent in the loop).

    uv run --group eval python -m eval.run_benchmark --suite scan --configs all
    uv run --group eval python -m eval.run_benchmark --suite scan --configs pg2-86m --limit 20
    uv run --group eval python -m eval.run_benchmark --suite lab --repeats 3        # about 2 hours
    uv run --group eval python -m eval.run_benchmark --suite lab --repeats 3 --reuse-off <batch>
    uv run --group eval python -m eval.run_benchmark --suite ablation --repeats 3   # about 2 hours
    uv run --group eval python -m eval.run_benchmark --suite latency                # about 12 min

The judge config runs only if the full pipeline's results say its uncertain band fits in the time
limit; otherwise it is skipped and the report says so, so a long run is never started by accident.
"""

import argparse
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from eval import ablation, latency
from eval.lab_suite import BatchRef, LabComparison, policy_hash, run_batch
from eval.lab_suite import write as write_lab
from eval.metrics import summarize
from eval.report import RESULTS_FILE, load_batch, run_info, write_report
from eval.scan_metrics import (
    DetectionStats,
    ItemResult,
    by_policy,
    by_score,
    choose_threshold,
    detection_stats,
    sweep,
    thresholds,
)
from eval.scan_report import Calibration, ConfigResult, ScanReport, write
from eval.scan_suite import (
    CONFIGS,
    PG2_86M,
    ScanConfig,
    ScanItem,
    judge_band_items,
    lab_items,
    load_deepset,
    models_used,
    run_config,
)
from promptshield.config import get_settings
from promptshield.models import LabRunOutcome
from promptshield.policy.schema import load_policy
from promptshield.provenance import git_description, machine_description

MAX_FPR = 0.05
JUDGE_SECONDS_PER_ITEM = 12.5  # measured for qwen3:4b-instruct on this laptop (D048)
TIME_LIMIT_MINUTES = 30
ABLATION_OFF_BATCH = "lab3off_20261114_1642"  # P7.2's shield-off batch (D066)


def power_state() -> str:
    """Latency depends on it: a laptop on battery runs slower."""
    import psutil

    battery = psutil.sensors_battery()
    if battery is None:
        return "no battery reported"
    return "on mains power" if battery.power_plugged else f"on battery ({battery.percent:.0f}%)"


def ollama_up(url: str) -> bool:
    import httpx

    try:
        return httpx.get(f"{url}/api/version", timeout=3, trust_env=False).status_code == 200
    except httpx.HTTPError:
        return False


def counts(items: Sequence[ScanItem]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for item in items:
        entry = out.setdefault(item.dataset, {"items": 0, "attacks": 0, "benign": 0})
        entry["items"] += 1
        entry["attacks" if item.attack else "benign"] += 1
    return out


def stats_by_dataset(
    results: Sequence[ItemResult], config: ScanConfig, threshold: float
) -> dict[str, DetectionStats]:
    flag = by_score(threshold) if config.score_only else by_policy
    datasets = sorted({result.dataset for result in results} - {"deepset-train"})
    return {
        name: detection_stats([r for r in results if r.dataset == name], flag) for name in datasets
    }


def flagged(results: Sequence[ItemResult], config: ScanConfig, threshold: float) -> set[str]:
    flag = by_score(threshold) if config.score_only else by_policy
    return {result.id for result in results if result.error is None and flag(result)}


@contextmanager
def keep_awake() -> Iterator[None]:
    """Ask Windows not to sleep while a long run is going. No admin rights needed, and the request
    ends with the process, so a crash can't leave the laptop unable to sleep."""
    if sys.platform != "win32":
        yield
        return
    import ctypes

    continuous, system_required = 0x80000000, 0x00000001
    kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
    kernel.SetThreadExecutionState(continuous | system_required)
    try:
        yield
    finally:
        kernel.SetThreadExecutionState(continuous)


def run_lab(args: argparse.Namespace) -> None:
    with keep_awake():
        _run_lab(args)


def _run_lab(args: argparse.Namespace) -> None:
    """Shield off, then on, then the per-batch reports and the side-by-side one."""
    settings = get_settings()
    results_file = settings.reports_dir / RESULTS_FILE
    echo = lambda line: print(line, flush=True)  # noqa: E731
    scenarios = [item.strip() for item in args.scenarios.split(",")] if args.scenarios else []
    # A subset is a smoke check: its label says so, so it can never pass for a full run.
    label = f"lab{args.repeats}" + ("smoke" if scenarios else "")
    off = args.reuse_off or run_batch("off", args.repeats, f"{label}off", echo, scenarios)
    on = run_batch("on", args.repeats, f"{label}on", echo, scenarios)
    refs: dict[str, BatchRef] = {}
    outcomes: dict[str, list[LabRunOutcome]] = {}
    for key, batch in (("off", off), ("on", on)):
        runs = load_batch(results_file, batch)
        if not runs:
            raise SystemExit(f"no runs found for batch {batch}")
        report = write_report(runs, run_info(runs, batch), settings.reports_dir)
        print(report, flush=True)
        outcomes[key] = runs
        refs[key] = BatchRef(
            batch=batch,
            shield=key == "on",
            repeats=max(run.repeat for run in runs) + 1,
            runs=len(runs),
            git=runs[0].git,
            report=report.name,
        )
    comparison = LabComparison(
        stamp=datetime.now(UTC).strftime("%Y%m%d_%H%M"),
        machine=machine_description(),
        power=power_state(),
        agent_model=settings.agent_model,
        num_ctx=outcomes["on"][0].num_ctx,  # what the runs recorded, not today's setting
        think=outcomes["on"][0].think,
        judge_model=settings.judge_model,
        classifier_threshold=settings.classifier_threshold,
        policy=policy_hash(settings.policy_path),
        off=refs["off"],
        on=refs["on"],
        off_summary=summarize(outcomes["off"]),
        on_summary=summarize(outcomes["on"]),
    )
    print(write_lab(comparison, outcomes["on"], settings.reports_dir))


def run_ablation(args: argparse.Namespace) -> None:
    with keep_awake():
        _run_ablation(args)


def _run_ablation(args: argparse.Namespace) -> None:
    """One shield-on lab batch per config, then the detection-only pass, then the report."""
    settings = get_settings()
    results_file = settings.reports_dir / RESULTS_FILE
    echo = lambda line: print(line, flush=True)  # noqa: E731
    scenarios = (
        [item.strip() for item in args.scenarios.split(",")]
        if args.scenarios
        else list(ablation.DEFAULT_SCENARIOS)
    )
    smoke = scenarios != list(ablation.DEFAULT_SCENARIOS)
    only = [] if args.configs == "all" else [name.strip() for name in args.configs.split(",")]
    chosen = ablation.configs(only)
    reference = load_batch(results_file, args.off_batch)
    if not reference:
        raise SystemExit(f"no runs found for the shield-off batch {args.off_batch}")
    rows: list[ablation.ConfigRow] = []
    for config in chosen:
        echo(f"ablation config {config.name}: layers {','.join(config.layers)}")
        batch = run_batch(
            "on", args.repeats, config.label(args.repeats, smoke), echo, scenarios, env=config.env()
        )
        rows.append(
            ablation.row(config.name, config.off, batch, load_batch(results_file, batch), scenarios)
        )
    scan_rows: list[ablation.ScanRow] = []
    scan_skipped = None if args.scan else "turned off with --no-scan"
    if args.scan:
        items = [*load_deepset("test"), *lab_items(settings.sink_port)]
        items = items[: args.limit] if args.limit else items
        for config in ablation.configs(["full", *(f"no-{name}" for name in ablation.SCAN_LAYERS)]):
            scan_config = CONFIGS["full"].model_copy(
                update={
                    "name": config.name,
                    "label": config.name,
                    "layers": [name for name in config.layers if name in ablation.SCAN_LAYERS],
                }
            )
            echo(f"scan {config.name}: {len(items)} items")
            results = run_config(scan_config, items, progress=echo)
            scan_rows.append(
                ablation.ScanRow(
                    name=config.name,
                    off=config.off,
                    by_dataset=stats_by_dataset(
                        results, scan_config, settings.classifier_threshold
                    ),
                )
            )
    report = ablation.AblationReport(
        stamp=datetime.now(UTC).strftime("%Y%m%d_%H%M"),
        machine=machine_description(),
        power=power_state(),
        agent_model=settings.agent_model,
        judge_model=settings.judge_model,
        classifier_threshold=settings.classifier_threshold,
        policy=policy_hash(settings.policy_path),
        repeats=args.repeats,
        scenarios=scenarios,
        reference_off=ablation.row("shield-off", None, args.off_batch, reference, scenarios),
        rows=rows,
        scan=scan_rows,
        scan_skipped=scan_skipped,
    )
    print(ablation.write(report, settings.reports_dir), flush=True)


def judge_sample(items: Sequence[ScanItem], size: int) -> list[ScanItem]:
    """Half attacks, half benign, in file order, so the sample is the same every run."""
    attacks = [item for item in items if item.attack][: size // 2]
    benign = [item for item in items if not item.attack][: size - len(attacks)]
    return [*attacks, *benign]


def run_latency(args: argparse.Namespace) -> None:
    with keep_awake():
        _run_latency(args)


def _run_latency(args: argparse.Namespace) -> None:
    settings = get_settings()
    echo = lambda line: print(line, flush=True)  # noqa: E731
    test, lab = load_deepset("test"), lab_items(settings.sink_port)
    if args.limit:
        test, lab = test[: args.limit], lab[: args.limit]
    items = [*test, *lab]
    power = power_state()
    echo(f"items: deepset-test {len(test)}, lab {len(lab)}; {power}")
    configs = latency.path_configs()
    only = list(configs) if args.configs == "all" else [n.strip() for n in args.configs.split(",")]
    unknown = [name for name in only if name not in configs]
    if unknown:
        raise SystemExit(f"unknown latency paths: {unknown}")
    paths: list[latency.PathResult] = []
    skipped: list[str] = []
    for name in only:
        config, label = configs[name]  # type: ignore[index]
        if config.judge_mode != "off" and not ollama_up(settings.ollama_url):
            skipped.append(f"{label}: Ollama isn't reachable at {settings.ollama_url}")
            continue
        chosen = judge_sample(lab, args.judge_sample) if name == "judge" else items
        rounds = args.rounds if config.judge_mode == "off" else 1
        echo(f"{label}: {len(chosen)} items x {rounds}")
        paths.append(
            latency.run_path(config, chosen, rounds, echo, per_layer=name == "fast", label=label)
        )
    with tempfile.TemporaryDirectory() as folder:
        echo("L4 action guard")
        guard = latency.run_guard(
            latency.guard_calls(settings.sink_port), args.guard_rounds, Path(folder)
        )
    report = latency.LatencyReport(
        stamp=datetime.now(UTC).strftime("%Y%m%d_%H%M"),
        git=git_description(),
        machine=machine_description(),
        power=power,
        judge_model=settings.judge_model,
        classifier_threshold=settings.classifier_threshold,
        task_alignment=settings.task_alignment,
        items={"deepset-test": len(test), "lab": len(lab)},
        paths=paths,
        guard=guard,
        skipped=skipped,
    )
    print(latency.write(report, settings.reports_dir), flush=True)
    print(latency.verdict_line(report), flush=True)


def main(argv: Sequence[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", choices=["scan", "lab", "ablation", "latency"], required=True)
    parser.add_argument(
        "--configs",
        default="all",
        help=f"scan: all, or a comma list of: {', '.join(CONFIGS)}; ablation: all, or of: "
        f"{', '.join(config.name for config in ablation.configs())}",
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="scan: first N items per split, for a quick check"
    )
    parser.add_argument("--repeats", type=int, default=1, help="lab: runs per scenario")
    parser.add_argument("--scenarios", help="lab: a comma list for a smoke check (default: all)")
    parser.add_argument(
        "--reuse-off", help="lab: an earlier shield-off batch, instead of a new one"
    )
    parser.add_argument(
        "--off-batch",
        default=ABLATION_OFF_BATCH,
        help="ablation: the shield-off batch used as the reference",
    )
    parser.add_argument(
        "--scan",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="ablation: also run the detection-only pass (a few minutes)",
    )
    parser.add_argument("--rounds", type=int, default=3, help="latency: passes on judge-free paths")
    parser.add_argument(
        "--judge-sample", type=int, default=20, help="latency: lab items for the judge path"
    )
    parser.add_argument("--guard-rounds", type=int, default=50, help="latency: L4 passes")
    args = parser.parse_args(argv)
    if args.suite == "lab":
        run_lab(args)
    elif args.suite == "ablation":
        run_ablation(args)
    elif args.suite == "latency":
        run_latency(args)
    else:
        run_scan(args)


def run_scan(args: argparse.Namespace) -> None:
    names = (
        list(CONFIGS)
        if args.configs == "all"
        else [name.strip() for name in args.configs.split(",")]
    )
    unknown = [name for name in names if name not in CONFIGS]
    if unknown:
        raise SystemExit(f"unknown configs: {unknown}")
    settings = get_settings()
    threshold = settings.classifier_threshold

    def cut(items: list[ScanItem]) -> list[ScanItem]:
        return items[: args.limit] if args.limit else items

    train, test, lab = (
        cut(load_deepset("train")),
        cut(load_deepset("test")),
        cut(lab_items(settings.sink_port)),
    )
    print(f"items: train {len(train)}, test {len(test)}, lab {len(lab)}", flush=True)

    configs: list[ConfigResult] = []
    skipped: list[str] = []
    calibration: Calibration | None = None
    flags: dict[str, set[str]] = {}
    full_results: list[ItemResult] | None = None
    for name in names:
        config = CONFIGS[name]
        if name == "full-judge":
            if full_results is None:
                skipped.append("full-judge: run `full` first, so the judge's load can be estimated")
                continue
            band = load_policy(settings.policy_path).thresholds.judge_band
            minutes = judge_band_items(full_results, band) * JUDGE_SECONDS_PER_ITEM / 60
            print(f"full-judge: about {minutes:.0f} min of judge calls", flush=True)
            if not ollama_up(settings.ollama_url):
                skipped.append(
                    f"full-judge: Ollama isn't reachable at {settings.ollama_url}; "
                    f"estimated {minutes:.0f} min of judge calls once it is"
                )
                continue
            if minutes > TIME_LIMIT_MINUTES:
                skipped.append(
                    f"full-judge: estimated {minutes:.0f} min, over the "
                    f"{TIME_LIMIT_MINUTES}-minute limit; ask first"
                )
                continue
        # Only the deployed classifier is calibrated, so only it needs the train split.
        items = [*(train if config.name == "pg2-86m" else []), *test, *lab]
        print(f"{config.label}: {len(items)} items", flush=True)
        results = run_config(config, items, progress=lambda line: print(line, flush=True))
        if name == "full":
            full_results = results
        configs.append(
            ConfigResult(
                name=name,
                label=config.label,
                models=models_used(results),
                flag_rule=f"L1 score >= {threshold:.2f}"
                if config.score_only
                else "decision != ALLOW",
                by_dataset=stats_by_dataset(results, config, threshold),
                results=results,
            )
        )
        flags[name] = flagged(results, config, threshold)
        if name == "pg2-86m":
            calibrating = [r for r in results if r.dataset == "deepset-train"]
            held_out = [r for r in results if r.dataset == "deepset-test"]
            points = sweep(calibrating, thresholds())
            chosen = choose_threshold(points, MAX_FPR)
            calibration = Calibration(
                model=PG2_86M,
                dataset="deepset-train",
                max_fpr=MAX_FPR,
                current=threshold,
                chosen=chosen,
                points=points,
                test_at_chosen=detection_stats(held_out, by_score(chosen.threshold))
                if chosen
                else None,
                test_at_current=detection_stats(held_out, by_score(threshold)),
            )

    # The chosen threshold changes more than L1's own score cut: weak findings now reach the policy
    # and can add up with other evidence. So the full pipeline runs again at the new value, and
    # the report shows both rows before anyone changes the config.
    chosen_point = calibration.chosen if calibration else None
    if chosen_point and chosen_point.threshold != threshold and full_results is not None:
        value = chosen_point.threshold
        config = CONFIGS["full"].model_copy(
            update={
                "name": "full-calibrated",
                "label": f"Full pipeline, L1 threshold {value:.2f} (calibrated)",
                "classifier_threshold": value,
            }
        )
        print(f"{config.label}: {len(test) + len(lab)} items", flush=True)
        results = run_config(config, [*test, *lab], progress=lambda line: print(line, flush=True))
        configs.append(
            ConfigResult(
                name=config.name,
                label=config.label,
                models=models_used(results),
                flag_rule="decision != ALLOW",
                by_dataset=stats_by_dataset(results, config, value),
                results=results,
            )
        )
        flags[config.name] = flagged(results, config, value)

    report = ScanReport(
        stamp=datetime.now(UTC).strftime("%Y%m%d_%H%M"),
        git=git_description(),
        machine=machine_description(),
        power=power_state(),
        datasets=counts([*train, *test, *lab]),
        configs=configs,
        calibration=calibration,
        skipped=skipped,
    )
    texts = {item.id: item.text for item in [*train, *test, *lab]}
    path = write(report, texts, flags, settings.reports_dir)
    print(path)
    if calibration and calibration.chosen:
        print(
            f"calibration: chosen L1 threshold {calibration.chosen.threshold:.2f} "
            f"(configured {threshold:.2f})"
        )


if __name__ == "__main__":
    main()
