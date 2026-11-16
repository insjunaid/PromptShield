"""The real RapidOCR model in the real worker. Slow: loading the model takes seconds."""

import base64
from time import perf_counter

import psutil
import pytest

from lab.attack_site import payloads
from lab.attack_site.build import render_attack_image, render_pixel_image
from promptshield.config import Settings
from promptshield.layers.base import ScanContext
from promptshield.layers.defaults import default_registry
from promptshield.models import ContentItem, SessionInfo
from promptshield.ocr import OcrEngine, ocr_installed
from promptshield.pipeline import ContentPipeline
from promptshield.policy.engine import PolicyEngine
from promptshield.policy.schema import load_policy

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not ocr_installed(), reason="RapidOCR is not installed"),
]

CONFIG = Settings(_env_file=None)  # type: ignore[call-arg]
SINK_PORT = 9999


def image_item(image: bytes) -> ContentItem:
    return ContentItem(
        kind="image", data=base64.b64encode(image).decode(), data_is_base64=True, source="t"
    )


async def test_the_a07_image_is_read_and_crosses_the_sanitize_line() -> None:
    pipeline = ContentPipeline(default_registry(CONFIG), ["L0", "L2"])
    image = render_attack_image(SINK_PORT)
    ctx = ScanContext(session=SessionInfo(), items=[image_item(image)])
    result = await pipeline.scan(ctx)
    engine = PolicyEngine(load_policy(CONFIG.policy_path))
    ocr_text = " ".join(s.text for s in result.segments if s.origin == "ocr")
    assert "read_file" in ocr_text
    assert payloads.SECRET_FILE in ocr_text
    rules = {item.rule_id: item for item in result.findings}
    assert rules["L2.IMAGE.ocr_text"].severity.value == "HIGH"
    assert engine.score(result.findings) >= engine.policy.thresholds.sanitize


async def test_a_plain_image_has_no_text() -> None:
    ocr = OcrEngine(CONFIG)
    try:
        assert (await ocr.read(render_pixel_image())).strip() == ""
    finally:
        ocr.stop()


async def test_stopping_frees_the_model_memory() -> None:
    ocr = OcrEngine(CONFIG)
    await ocr.read(render_pixel_image())
    assert ocr._process is not None
    root = psutil.Process(ocr._process.pid)
    processes = [root, *root.children(recursive=True)]
    loaded = sum(process.memory_info().rss for process in processes)
    ocr.stop()
    _, alive = psutil.wait_procs(processes, timeout=5)
    assert alive == []
    assert loaded > 50_000_000  # the model really was in one of these processes


async def test_the_model_loads_once() -> None:
    """The second image must not pay the load cost again."""
    ocr = OcrEngine(CONFIG)
    image = render_attack_image(SINK_PORT)
    try:
        started = perf_counter()
        await ocr.read(image)
        first = perf_counter() - started
        started = perf_counter()
        await ocr.read(image)
        second = perf_counter() - started
    finally:
        ocr.stop()
    assert second < first
