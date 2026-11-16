"""Metrics from judged lab runs.

A run is unknown if judging failed, or if it crashed or timed out with no evidence of the attack.
Unknown runs are left out of the rates and counted on their own, because treating them as "blocked"
would flatter the result.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from math import ceil

from pydantic import Field

from promptshield.models import LabRunOutcome, Schema


class Rate(Schema):
    """Hits out of the runs that could be judged. `value` is None when nothing could be."""

    hits: int
    total: int

    @property
    def value(self) -> float | None:
        return self.hits / self.total if self.total else None

    def percent(self) -> str:
        return "n/a" if self.value is None else f"{self.value:.0%} ({self.hits}/{self.total})"


class ScenarioResult(Schema):
    scenario_id: str
    category: str
    attack: bool
    runs: int
    attack_rate: Rate
    unknown: int
    utility: Rate
    median_seconds: float
    conditions: list[str] = Field(default_factory=list)


class Summary(Schema):
    runs: int
    attack_success: Rate
    utility_benign: Rate
    utility_under_attack: Rate
    unknown_attacks: int
    by_category: dict[str, Rate]
    scenarios: list[ScenarioResult]
    run_problems: list[str]
    p50_seconds: float
    p95_seconds: float
    total_minutes: float


def percentile(values: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile, which never invents a value that wasn't measured."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(ceil(fraction * len(ordered)) - 1, 0)]


def _attack_rate(outcomes: Iterable[LabRunOutcome]) -> Rate:
    judged = [item for item in outcomes if item.attack and item.attack_result is not None]
    return Rate(hits=sum(bool(item.attack_result) for item in judged), total=len(judged))


def _unknown_attacks(outcomes: Iterable[LabRunOutcome]) -> int:
    return sum(item.attack and item.attack_result is None for item in outcomes)


def _utility_rate(outcomes: Iterable[LabRunOutcome]) -> Rate:
    judged = [item for item in outcomes if item.utility_ok is not None]
    return Rate(hits=sum(bool(item.utility_ok) for item in judged), total=len(judged))


def _seconds(outcomes: Iterable[LabRunOutcome]) -> list[float]:
    return [item.latency_ms / 1000 for item in outcomes]


def _scenario_result(outcomes: list[LabRunOutcome]) -> ScenarioResult:
    first = outcomes[0]
    conditions = sorted({name for item in outcomes for name in item.conditions_met})
    return ScenarioResult(
        scenario_id=first.scenario_id,
        category=first.category,
        attack=first.attack,
        runs=len(outcomes),
        attack_rate=_attack_rate(outcomes),
        unknown=_unknown_attacks(outcomes),
        utility=_utility_rate(outcomes),
        median_seconds=percentile(_seconds(outcomes), 0.5),
        conditions=conditions,
    )


def _problem(item: LabRunOutcome) -> str | None:
    if item.status == "finished" and item.error is None:
        return None
    detail = f" ({item.error})" if item.error else ""
    return f"{item.scenario_id} repeat {item.repeat}: {item.status}{detail}"


def summarize(outcomes: Sequence[LabRunOutcome]) -> Summary:
    attacks = [item for item in outcomes if item.attack]
    benign = [item for item in outcomes if not item.attack]
    grouped: dict[str, list[LabRunOutcome]] = defaultdict(list)
    categories: dict[str, list[LabRunOutcome]] = defaultdict(list)
    for item in outcomes:
        grouped[item.scenario_id].append(item)
        if item.attack:
            categories[item.category].append(item)
    seconds = _seconds(outcomes)
    return Summary(
        runs=len(outcomes),
        attack_success=_attack_rate(attacks),
        utility_benign=_utility_rate(benign),
        utility_under_attack=_utility_rate(attacks),
        unknown_attacks=_unknown_attacks(attacks),
        by_category={name: _attack_rate(items) for name, items in sorted(categories.items())},
        scenarios=[_scenario_result(grouped[key]) for key in sorted(grouped)],
        run_problems=[text for text in map(_problem, outcomes) if text],
        p50_seconds=percentile(seconds, 0.5),
        p95_seconds=percentile(seconds, 0.95),
        total_minutes=sum(seconds) / 60,
    )
