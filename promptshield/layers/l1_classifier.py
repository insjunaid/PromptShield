"""L1: a prompt-injection classifier run on every segment, visible and hidden.

The model runs on onnxruntime alone, so the shield never loads torch. Exported files come from
`scripts/export_classifiers.py`. Missing files raise `LayerSkipped`, which the pipeline treats as an
error for L1, so scans fail closed instead of passing unchecked.

Classifiers silently drop text past their context, so windows are checked with the real tokenizer
and split again if the cheap estimate was wrong. Padding must never become a bypass.
"""

import asyncio
import json
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np
import structlog

from promptshield.config import Settings
from promptshield.layers.base import LayerSkipped, ScanContext
from promptshield.models import Finding, LayerName, Segment, SegmentOrigin, Severity
from promptshield.text.chunking import chunk_text

logger = structlog.get_logger(__name__)

MODEL_FILE = "model.onnx"
TOKENIZER_FILE = "tokenizer.json"
MANIFEST_FILE = "manifest.json"
HIGH_SCORE = 0.9
# The second opinion misfires on non-Latin text (D046), so it only reads mostly-Latin segments.
LATIN_SHARE = 0.9
MEDIUM_SCORE = 0.5
RULE_NAME = re.compile(r"[^a-z0-9]+")


def model_folder(models_dir: Path, model_id: str, precision: str) -> Path:
    return models_dir / model_id.replace("/", "--") / precision


def rule_id(model_id: str) -> str:
    return "L1.CLASSIFIER." + RULE_NAME.sub("_", model_id.split("/")[-1].lower()).strip("_")


class Classifier(Protocol):
    model_id: str
    max_tokens: int

    def token_count(self, text: str) -> int: ...

    def scores(self, texts: list[str]) -> list[float]: ...


class OnnxClassifier:
    """One exported model. Loading is slow, so the layer builds this once and keeps it."""

    def __init__(self, folder: Path, threads: int, max_tokens: int) -> None:
        import onnxruntime  # type: ignore[import-untyped]
        from tokenizers import Tokenizer  # type: ignore[import-untyped]

        manifest = json.loads((folder / MANIFEST_FILE).read_text(encoding="utf-8"))
        self.model_id: str = manifest["model_id"]
        self.max_tokens = max_tokens
        self._malicious = int(manifest["malicious_index"])
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = threads
        self._session = onnxruntime.InferenceSession(
            str(folder / MODEL_FILE), options, providers=["CPUExecutionProvider"]
        )
        self._inputs = {item.name for item in self._session.get_inputs()}
        self._tokenizer = Tokenizer.from_file(str(folder / TOKENIZER_FILE))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        self._pad_id = _pad_id(folder, self._tokenizer)

    def token_count(self, text: str) -> int:
        """Includes the special tokens the model adds, since they use up context too."""
        return len(self._tokenizer.encode(text).ids)

    def scores(self, texts: list[str]) -> list[float]:
        encodings = self._tokenizer.encode_batch(texts)
        width = max(len(encoding.ids) for encoding in encodings)
        ids = np.full((len(texts), width), self._pad_id, dtype=np.int64)
        mask = np.zeros((len(texts), width), dtype=np.int64)
        for row, encoding in enumerate(encodings):
            ids[row, : len(encoding.ids)] = encoding.ids
            mask[row, : len(encoding.ids)] = 1
        feed = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.zeros_like(ids)
        logits = self._session.run(None, {name: feed[name] for name in self._inputs})[0]
        shifted = np.exp(logits - logits.max(axis=1, keepdims=True))
        probabilities = shifted / shifted.sum(axis=1, keepdims=True)
        return [float(value) for value in probabilities[:, self._malicious]]


def _pad_id(folder: Path, tokenizer: object) -> int:
    config_path = folder / "tokenizer_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    pad = config.get("pad_token")
    if isinstance(pad, dict):
        pad = pad.get("content")
    found = tokenizer.token_to_id(str(pad)) if pad else None  # type: ignore[attr-defined]
    return int(found) if found is not None else 0


@dataclass(frozen=True)
class _Window:
    segment: int
    text: str


def _fit(text: str, classifier: Classifier) -> list[str]:
    """Split until each piece fits the real context. The estimate is pessimistic, so this is rare:
    characters that tokenize into several pieces, such as some emoji, are the usual cause."""
    if classifier.token_count(text) <= classifier.max_tokens or len(text) < 2:
        return [text]
    middle = len(text) // 2
    space = text.rfind(" ", middle // 2, middle + middle // 2)
    cut = space if space > 0 else middle
    return [*_fit(text[:cut], classifier), *_fit(text[cut:], classifier)]


def is_mostly_latin(text: str) -> bool:
    """Text with no letters, such as base64 or numbers, counts as Latin."""
    letters = [char for char in text if char.isalpha()]
    if not letters:
        return True
    latin = sum(
        char.isascii() or unicodedata.name(char, "").startswith("LATIN") for char in letters
    )
    return latin / len(letters) >= LATIN_SHARE


Best = dict[int, tuple[float, str, str]]  # segment index -> score, window text, model id


def _severity(score: float) -> Severity:
    if score >= HIGH_SCORE:
        return Severity.HIGH
    return Severity.MEDIUM if score >= MEDIUM_SCORE else Severity.LOW


class ClassifierLayer:
    name: LayerName = "L1"

    def __init__(
        self,
        settings: Settings,
        classifier: Classifier | None = None,
        second: Classifier | None = None,
    ) -> None:
        self._settings = settings
        self._classifier = classifier
        self._second = second
        self.refits = 0  # windows the estimate got wrong, for measuring the estimate

    def _model(self) -> Classifier:
        if self._classifier is None:
            self._classifier = _load(self._settings)
        return self._classifier

    def _second_model(self) -> Classifier | None:
        """Only when switched on. A missing export then fails closed, like a missing primary."""
        if self._second is None and self._settings.classifier_second_opinion:
            self._second = _load_second(self._settings)
        return self._second

    async def warmup(self) -> None:
        """Load the models and run them once, so the first real scan isn't the slow one."""

        def warm() -> None:
            self._model().scores(["warm up"])
            second = self._second_model()
            if second is not None:
                second.scores(["warm up"])

        await asyncio.to_thread(warm)

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        segments = [segment for segment in ctx.segments if segment.text.strip()]
        if not segments:
            return []
        return await asyncio.to_thread(self._classify, segments)

    def _classify(self, segments: Sequence[Segment]) -> list[Finding]:
        best: Best = {}
        self._keep_best(best, list(range(len(segments))), segments, self._model())
        second = self._second_model()
        if second is not None:
            latin = [index for index, item in enumerate(segments) if is_mostly_latin(item.text)]
            self._keep_best(best, latin, segments, second)
        return self._findings(segments, best)

    def _keep_best(
        self,
        best: Best,
        indexes: list[int],
        segments: Sequence[Segment],
        classifier: Classifier,
    ) -> None:
        """Windows are fitted per model, because each tokenizer counts differently."""
        windows = self._windows([segments[index] for index in indexes], classifier)
        scores = self._score(windows, classifier)
        for window, score in zip(windows, scores, strict=True):
            index = indexes[window.segment]
            if score > best.get(index, (-1.0, "", ""))[0]:
                best[index] = (score, window.text, classifier.model_id)

    def _windows(self, segments: Sequence[Segment], classifier: Classifier) -> list[_Window]:
        settings = self._settings
        # Two tokens are kept back for the start and end markers the model adds.
        budget = settings.chunk_max_tokens - 2
        windows: list[_Window] = []
        for index, segment in enumerate(segments):
            chunks = chunk_text(
                segment.text, budget, settings.chunk_overlap_tokens, settings.chunk_chars_per_token
            )
            for chunk in chunks:
                pieces = _fit(chunk.text, classifier)
                self.refits += len(pieces) - 1
                windows.extend(_Window(index, piece) for piece in pieces)
        return windows

    def _score(self, windows: list[_Window], classifier: Classifier) -> list[float]:
        """Batched, shortest first, so padding stays small."""
        order = sorted(range(len(windows)), key=lambda index: len(windows[index].text))
        scores = [0.0] * len(windows)
        size = self._settings.classifier_batch_size
        for start in range(0, len(order), size):
            batch = order[start : start + size]
            for index, score in zip(
                batch, classifier.scores([windows[i].text for i in batch]), strict=True
            ):
                scores[index] = score
        return scores

    def _threshold(self, model_id: str) -> float:
        """Each model's scores have their own scale; the calibrated value fits Prompt Guard 2."""
        settings = self._settings
        if model_id == settings.fallback_classifier_model:
            return settings.fallback_classifier_threshold
        return settings.classifier_threshold

    def _findings(self, segments: Sequence[Segment], best: Best) -> list[Finding]:
        """The strongest hit per origin, so the policy can weigh hidden hits up without many
        weak visible windows adding up through noisy-OR. The rule names the model that scored."""
        strongest: dict[SegmentOrigin, tuple[float, str, str]] = {}
        for index, (score, text, model_id) in best.items():
            origin = segments[index].origin
            threshold = self._threshold(model_id)
            if score >= threshold and score > strongest.get(origin, (-1.0, "", ""))[0]:
                strongest[origin] = (score, text, model_id)
        return [
            Finding(
                layer="L1",
                rule_id=rule_id(model_id),
                title="Text classified as prompt injection",
                severity=_severity(score),
                score=score,
                evidence=text,
                segment_origin=origin,
                latency_ms=0,
            )
            for origin, (score, text, model_id) in strongest.items()
        ]


def _load(settings: Settings) -> Classifier:
    """The configured model if exported, else the fallback. The one that ran is logged."""
    for model_id in (settings.classifier_model, settings.fallback_classifier_model):
        folder = model_folder(settings.models_dir, model_id, settings.classifier_precision)
        if (folder / MODEL_FILE).exists():
            logger.info(
                "classifier_loading", model=model_id, precision=settings.classifier_precision
            )
            return OnnxClassifier(folder, settings.classifier_threads, settings.chunk_max_tokens)
    raise LayerSkipped("no classifier installed: run `promptshield setup`")


def _load_second(settings: Settings) -> Classifier:
    model_id = settings.fallback_classifier_model
    folder = model_folder(settings.models_dir, model_id, settings.classifier_precision)
    if not (folder / MODEL_FILE).exists():
        raise LayerSkipped("second opinion is on but not exported: run the export script")
    logger.info("second_opinion_loading", model=model_id)
    return OnnxClassifier(folder, settings.classifier_threads, settings.chunk_max_tokens)
