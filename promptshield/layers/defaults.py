"""The layers a running shield uses. New layers are added here as they are built."""

from promptshield.config import Settings
from promptshield.layers.canary import CanaryLayer, CanaryStore
from promptshield.layers.l0_normalize import NormalizeLayer
from promptshield.layers.l1_classifier import ClassifierLayer
from promptshield.layers.l2_hidden import HiddenContentLayer
from promptshield.layers.l3_judge import JudgeLayer
from promptshield.ocr import OcrEngine, ocr_installed
from promptshield.pipeline import LayerRegistry


def _hidden_content_layer(settings: Settings) -> HiddenContentLayer:
    ocr = OcrEngine(settings) if ocr_installed() else None
    return HiddenContentLayer(ocr, settings.ocr_max_images)


def default_registry(settings: Settings, canaries: CanaryStore | None = None) -> LayerRegistry:
    registry = LayerRegistry()
    store = canaries or CanaryStore()
    registry.register("CANARY", lambda: CanaryLayer(store))
    registry.register("L0", lambda: NormalizeLayer(settings))
    registry.register("L2", lambda: _hidden_content_layer(settings))
    registry.register("L1", lambda: ClassifierLayer(settings))
    registry.register("L3", lambda: JudgeLayer(settings))
    return registry
