from eval.scan_metrics import (
    ItemResult,
    SweepPoint,
    by_policy,
    by_score,
    choose_threshold,
    detection_stats,
    sweep,
    thresholds,
)
from promptshield.models import Decision


def item(
    attack: bool,
    *,
    score: float | None = None,
    decision: Decision | None = None,
    ms: float = 10.0,
    error: str | None = None,
) -> ItemResult:
    return ItemResult(
        id="x",
        dataset="d",
        attack=attack,
        l1_score=score,
        decision=decision,
        latency_ms=ms,
        error=error,
    )


def test_precision_recall_and_f1_from_flags() -> None:
    results = [
        item(True, score=0.9),
        item(True, score=0.2),
        item(False, score=0.7),
        item(False, score=0.1),
    ]
    stats = detection_stats(results, by_score(0.5))
    assert (
        stats.true_positive,
        stats.false_negative,
        stats.false_positive,
        stats.true_negative,
    ) == (1, 1, 1, 1)
    assert stats.precision == 0.5
    assert stats.recall == 0.5
    assert stats.f1 == 0.5
    assert stats.flagged_benign_rate == 0.5
    assert stats.block_fpr is None  # no policy decisions: blocking isn't defined


def test_policy_fpr_counts_blocks_and_sanitize_is_separate() -> None:
    results = [
        item(False, decision=Decision.BLOCK),
        item(False, decision=Decision.SANITIZE),
        item(False, decision=Decision.ALLOW),
        item(False, decision=Decision.ALLOW),
        item(True, decision=Decision.SANITIZE),
    ]
    stats = detection_stats(results, by_policy)
    assert stats.block_fpr == 0.25
    assert stats.sanitized_benign_rate == 0.25
    assert stats.flagged_benign_rate == 0.5
    assert stats.recall == 1.0  # sanitizing an attack counts as catching it


def test_errors_are_counted_not_scored() -> None:
    stats = detection_stats([item(True, score=0.9), item(True, error="boom")], by_score(0.5))
    assert stats.errors == 1
    assert stats.attacks == 1
    assert stats.recall == 1.0


def test_empty_classes_give_none_not_a_crash() -> None:
    stats = detection_stats([item(True, score=0.1)], by_score(0.5))
    assert stats.precision is None
    assert stats.f1 is None
    assert stats.flagged_benign_rate is None


def test_latency_percentiles() -> None:
    stats = detection_stats(
        [item(False, ms=float(value)) for value in range(1, 101)], by_score(0.5)
    )
    assert stats.p50_ms == 50.5
    assert stats.p99_ms is not None and stats.p99_ms > 98


def test_thresholds_run_from_ten_to_ninety_five_percent() -> None:
    points = thresholds()
    assert points[0] == 0.10 and points[-1] == 0.95 and len(points) == 18


def test_sweep_trades_recall_for_fpr() -> None:
    results = [
        item(True, score=0.95),
        item(True, score=0.6),
        item(False, score=0.55),
        item(False, score=0.05),
    ]
    points = {p.threshold: p for p in sweep(results, [0.5, 0.9])}
    assert (points[0.5].recall, points[0.5].fpr) == (1.0, 0.5)
    assert (points[0.9].recall, points[0.9].fpr) == (0.5, 0.0)


def test_choose_the_best_recall_within_the_fpr_limit() -> None:
    points = [
        SweepPoint(threshold=0.3, precision=0.7, recall=0.95, fpr=0.20),
        SweepPoint(threshold=0.6, precision=0.9, recall=0.80, fpr=0.04),
        SweepPoint(threshold=0.7, precision=0.9, recall=0.80, fpr=0.02),
        SweepPoint(threshold=0.9, precision=1.0, recall=0.50, fpr=0.00),
    ]
    chosen = choose_threshold(points)
    assert chosen is not None and chosen.threshold == 0.7  # same recall, lower FPR


def test_no_threshold_is_chosen_when_none_is_safe_enough() -> None:
    assert choose_threshold([SweepPoint(threshold=0.5, precision=0.5, recall=1.0, fpr=0.3)]) is None
