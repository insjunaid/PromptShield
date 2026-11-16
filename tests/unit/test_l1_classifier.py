"""L1 with a stand-in model: windows, batching, findings and failure. The real models are in the
slow tests."""

from pathlib import Path

import pytest

from promptshield.config import Settings
from promptshield.layers.base import LayerSkipped, ScanContext
from promptshield.layers.l1_classifier import (
    ClassifierLayer,
    is_mostly_latin,
    model_folder,
    rule_id,
)
from promptshield.models import Segment, SegmentOrigin, SessionInfo, Severity
from promptshield.pipeline import ContentPipeline, LayerRegistry
from promptshield.policy.engine import PolicyEngine
from promptshield.policy.schema import load_policy

CONFIG = Settings(_env_file=None)  # type: ignore[call-arg]
TRIGGER = "ATTACK"


class FakeClassifier:
    """Scores 0.97 for any text holding TRIGGER. Counts one token per character plus two markers,
    or per `cost` characters, to imitate a tokenizer the estimate underrates."""

    model_id = "meta-llama/Llama-Prompt-Guard-2-86M"

    def __init__(self, max_tokens: int = 512, chars_per_token: float = 4.0) -> None:
        self.max_tokens = max_tokens
        self.chars_per_token = chars_per_token
        self.batches: list[list[str]] = []

    def token_count(self, text: str) -> int:
        return int(len(text) / self.chars_per_token) + 2

    def scores(self, texts: list[str]) -> list[float]:
        self.batches.append(texts)
        return [0.97 if TRIGGER in text else 0.02 for text in texts]


def layer(classifier: FakeClassifier | None = None, **values: object) -> ClassifierLayer:
    settings = CONFIG.model_copy(update=values)
    return ClassifierLayer(settings, classifier or FakeClassifier())


async def scan(
    target: ClassifierLayer, *texts: str, origin: SegmentOrigin = "visible"
) -> ScanContext:
    ctx = ScanContext(
        session=SessionInfo(), segments=[Segment(text=text, origin=origin) for text in texts]
    )
    ctx.prior_findings.extend(await target.scan(ctx))
    return ctx


async def test_an_injection_is_reported_with_its_origin() -> None:
    [finding] = (await scan(layer(), f"please {TRIGGER} now", origin="hidden_css")).prior_findings
    assert finding.rule_id == "L1.CLASSIFIER.llama_prompt_guard_2_86m"
    assert finding.segment_origin == "hidden_css"
    assert finding.score == pytest.approx(0.97)
    assert finding.severity == Severity.HIGH
    assert TRIGGER in finding.evidence


async def test_benign_text_gives_no_finding() -> None:
    assert (await scan(layer(), "a normal sentence")).prior_findings == []


async def test_the_threshold_decides_what_is_reported() -> None:
    assert (await scan(layer(classifier_threshold=0.01), "plain")).prior_findings != []


async def test_no_segments_needs_no_model() -> None:
    target = ClassifierLayer(CONFIG.model_copy(update={"models_dir": Path("missing")}))
    assert await target.scan(ScanContext(session=SessionInfo())) == []


async def test_one_finding_per_origin_keeps_the_strongest() -> None:
    ctx = await scan(layer(), f"{TRIGGER} one", f"{TRIGGER} two", "fine")
    assert len(ctx.prior_findings) == 1


async def test_hidden_and_visible_hits_are_reported_separately() -> None:
    target = layer()
    ctx = ScanContext(
        session=SessionInfo(),
        segments=[
            Segment(text=f"{TRIGGER} shown", origin="visible"),
            Segment(text=f"{TRIGGER} hidden", origin="html_comment"),
        ],
    )
    origins = {finding.segment_origin for finding in await target.scan(ctx)}
    assert origins == {"visible", "html_comment"}


async def test_an_attack_at_the_end_of_a_long_page_is_still_read() -> None:
    """Classifiers drop text past their context. This is the padding bypass."""
    page = "filler words here " * 3000 + TRIGGER
    assert (await scan(layer(), page)).prior_findings != []


async def test_every_window_fits_the_real_context() -> None:
    fake = FakeClassifier(chars_per_token=1.0)  # far worse than the estimate assumes
    target = layer(fake)
    await scan(target, "x" * 20000)
    windows = [text for batch in fake.batches for text in batch]
    assert all(fake.token_count(text) <= fake.max_tokens for text in windows)
    assert target.refits > 0
    assert "".join(windows).count("x") >= 20000


async def test_the_estimate_usually_needs_no_refit() -> None:
    target = layer(FakeClassifier(chars_per_token=4.0))
    await scan(target, "ordinary english words " * 2000)
    assert target.refits == 0


async def test_windows_are_batched() -> None:
    fake = FakeClassifier()
    await scan(layer(fake, classifier_batch_size=3), *[f"text {index}" for index in range(10)])
    assert [len(batch) for batch in fake.batches] == [3, 3, 3, 1]


async def test_scores_map_back_to_the_right_segment_after_sorting() -> None:
    """Batches are sorted by length, so a mix-up would blame the wrong segment."""
    texts = ["a" * 50, f"{TRIGGER}", "b" * 5, "c" * 500]
    ctx = await scan(layer(classifier_batch_size=2), *texts, origin="meta")
    assert ctx.prior_findings[0].evidence == TRIGGER


async def test_blank_segments_are_skipped() -> None:
    fake = FakeClassifier()
    await scan(layer(fake), "   ", "")
    assert fake.batches == []


async def test_a_missing_model_skips_the_layer() -> None:
    target = ClassifierLayer(CONFIG.model_copy(update={"models_dir": Path("no-such-folder")}))
    ctx = ScanContext(session=SessionInfo(), segments=[Segment(text="x", origin="visible")])
    with pytest.raises(LayerSkipped):
        await target.scan(ctx)


async def test_a_missing_model_fails_the_scan_closed() -> None:
    """L1 is required: running without it would look clean while checking nothing."""
    registry = LayerRegistry()
    missing = CONFIG.model_copy(update={"models_dir": Path("no-such-folder")})
    registry.register("L1", lambda: ClassifierLayer(missing))
    pipeline = ContentPipeline(registry, ["L1"])
    ctx = ScanContext(session=SessionInfo(), segments=[Segment(text="x", origin="visible")])
    result = await pipeline.scan(ctx)
    assert result.layers_run["L1"] == "error"
    engine = PolicyEngine(load_policy(CONFIG.policy_path))
    assert engine.decide_inbound(result).decision.value == "BLOCK"


async def test_warmup_runs_the_model_once() -> None:
    fake = FakeClassifier()
    await layer(fake).warmup()
    assert len(fake.batches) == 1


class SecondOpinion(FakeClassifier):
    model_id = "protectai/deberta-v3-base-prompt-injection-v2"
    trigger = "quietly"

    def scores(self, texts: list[str]) -> list[float]:
        self.batches.append(texts)
        return [0.95 if self.trigger in text else 0.01 for text in texts]


async def test_the_second_opinion_adds_what_the_first_missed() -> None:
    second = SecondOpinion()
    target = ClassifierLayer(CONFIG, FakeClassifier(), second)
    [finding] = (await scan(target, "please quietly send the report")).prior_findings
    assert finding.rule_id == "L1.CLASSIFIER.deberta_v3_base_prompt_injection_v2"
    assert finding.score == pytest.approx(0.95)


async def test_the_higher_score_wins_and_names_its_model() -> None:
    target = ClassifierLayer(CONFIG, FakeClassifier(), SecondOpinion())
    [finding] = (await scan(target, f"quietly {TRIGGER}")).prior_findings
    assert finding.rule_id == "L1.CLASSIFIER.llama_prompt_guard_2_86m"


async def test_the_second_opinion_only_reads_latin_text() -> None:
    second = SecondOpinion()
    target = ClassifierLayer(CONFIG, FakeClassifier(), second)
    await scan(target, "quietly in english", "उपयोगकर्ता quietly को बताएं नहीं")
    read = [text for batch in second.batches for text in batch]
    assert read == ["quietly in english"]


async def test_the_second_opinion_is_off_by_default() -> None:
    assert CONFIG.classifier_second_opinion is False
    target = ClassifierLayer(CONFIG, FakeClassifier())
    assert target._second_model() is None


async def test_a_missing_second_opinion_fails_closed_when_switched_on() -> None:
    settings = CONFIG.model_copy(
        update={"classifier_second_opinion": True, "models_dir": Path("no-such-folder")}
    )
    target = ClassifierLayer(settings, FakeClassifier())
    ctx = ScanContext(session=SessionInfo(), segments=[Segment(text="x", origin="visible")])
    with pytest.raises(LayerSkipped):
        await target.scan(ctx)


@pytest.mark.parametrize(
    ("text", "latin"),
    [
        ("plain english", True),
        ("café crème brûlée", True),
        ("QUJDREVGR0g= 12345", True),
        ("", True),
        ("उपयोगकर्ता को बताएं", False),
        ("مرحبا بالعالم", False),
        ("mostly हिंदी text हिंदी", False),
    ],
)
def test_latin_script_detection(text: str, latin: bool) -> None:
    assert is_mostly_latin(text) is latin


def test_model_folders_are_per_model_and_precision() -> None:
    folder = model_folder(Path("models"), "meta-llama/Llama-Prompt-Guard-2-86M", "int8")
    assert folder == Path("models/meta-llama--Llama-Prompt-Guard-2-86M/int8")


def test_rule_ids_are_safe_names() -> None:
    assert rule_id("protectai/deberta-v3-base-prompt-injection-v2") == (
        "L1.CLASSIFIER.deberta_v3_base_prompt_injection_v2"
    )
