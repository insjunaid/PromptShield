"""The scan suite: detection only, no agent. Items go through the real app's /v1/scan.

Datasets:
- `deepset/prompt-injections` (Apache-2.0), downloaded at run time into data/hf (git-ignored), never
  committed. Its train split calibrates the L1 threshold; its test split is only for reporting.
- `lab`: the attack site's pages plus the hand-written attack and benign texts from the tests. These
  shaped earlier tuning (D046-D049), so they are development data, reported separately.

Each config is a fresh app with its own settings, built and closed in turn, so only one classifier
is in memory at a time (the dev laptop has about 2 GB free).
"""

import gc
import os
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from time import perf_counter
from typing import Any, Literal

from fastapi.testclient import TestClient

from eval.scan_metrics import ItemResult
from lab.attack_site.build import PAGES, build_site
from promptshield.api.server import create_app
from promptshield.config import REPO_ROOT, Settings
from promptshield.models import Decision, LayerName, Schema
from tests.fixtures.wording import (
    AWKWARD_BENIGN,
    COMMON_ATTACKS,
    ORDINARY_TEXT,
    PARAPHRASED_ATTACKS,
)

DEEPSET = "deepset/prompt-injections"
HF_CACHE = REPO_ROOT / "data" / "hf"
TASK = "Summarize this for me."
BASE_URL = "http://127.0.0.1"


class ScanItem(Schema):
    id: str
    dataset: str  # "deepset-train", "deepset-test" or "lab"
    text: str
    attack: bool
    source: str


class ScanConfig(Schema):
    name: str
    label: str
    layers: list[LayerName]
    classifier_model: str | None = None
    judge_mode: Literal["off", "uncertain", "always"] = "off"
    # Score-only configs run L1 with its threshold at 0, so every item's raw score is kept and
    # any threshold can be applied afterwards. They have no meaningful policy decision.
    score_only: bool = False
    classifier_threshold: float | None = None  # overrides the configured value (calibration)


PG2_86M = "meta-llama/Llama-Prompt-Guard-2-86M"
PG2_22M = "meta-llama/Llama-Prompt-Guard-2-22M"
PROTECTAI = "protectai/deberta-v3-base-prompt-injection-v2"

CONFIGS: dict[str, ScanConfig] = {
    item.name: item
    for item in [
        ScanConfig(
            name="pg2-86m",
            label="PG2-86M alone",
            layers=["L0", "L1"],
            classifier_model=PG2_86M,
            score_only=True,
        ),
        ScanConfig(
            name="pg2-22m",
            label="PG2-22M alone",
            layers=["L0", "L1"],
            classifier_model=PG2_22M,
            score_only=True,
        ),
        ScanConfig(
            name="protectai-v2",
            label="ProtectAI v2 alone",
            layers=["L0", "L1"],
            classifier_model=PROTECTAI,
            score_only=True,
        ),
        ScanConfig(name="l2-only", label="L2 only (hidden content rules)", layers=["L0", "L2"]),
        ScanConfig(
            name="full",
            label="Full pipeline (L0+L2+L1+canary)",
            layers=["L0", "L2", "L1", "CANARY"],
            classifier_model=PG2_86M,
        ),
        ScanConfig(
            name="full-judge",
            label="Full + L3 judge (uncertain band)",
            layers=["L0", "L2", "L1", "CANARY", "L3"],
            classifier_model=PG2_86M,
            judge_mode="uncertain",
        ),
    ]
}


# ---- Data -----------------------------------------------------------------------------------


def _hf_environment() -> None:
    """Keep every Hugging Face download inside the project (data/ is git-ignored)."""
    HF_CACHE.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("HF_HOME", str(HF_CACHE))
    os.environ.setdefault("HF_DATASETS_CACHE", str(HF_CACHE / "datasets"))
    os.environ.setdefault("HF_HUB_CACHE", str(HF_CACHE / "hub"))


def deepset_items(rows: Sequence[dict[str, Any]], split: str) -> list[ScanItem]:
    """Label 1 is an injection in this dataset."""
    return [
        ScanItem(
            id=f"deepset-{split}-{index:04d}",
            dataset=f"deepset-{split}",
            text=str(row["text"]),
            attack=int(row["label"]) == 1,
            source=f"dataset:{DEEPSET}",
        )
        for index, row in enumerate(rows)
    ]


def load_deepset(split: Literal["train", "test"]) -> list[ScanItem]:
    _hf_environment()
    from datasets import load_dataset  # type: ignore[import-untyped]  # eval group only

    rows = load_dataset(DEEPSET, split=split, cache_dir=str(HF_CACHE / "datasets"))
    return deepset_items(list(rows), split)


def lab_items(sink_port: int) -> list[ScanItem]:
    """Attack-site pages as web_fetch returns them, and the hand-written texts."""
    items: list[ScanItem] = []
    with tempfile.TemporaryDirectory() as folder:
        site = Path(folder)
        build_site(site, sink_port)
        for page in PAGES:
            items.append(
                ScanItem(
                    id=f"lab-page-{page.id}",
                    dataset="lab",
                    text=(site / page.filename).read_text(encoding="utf-8"),
                    attack=page.id.startswith("A"),
                    source=f"web_fetch:{page.filename}",
                )
            )
    sets = [
        ("common", COMMON_ATTACKS, True),
        ("paraphrased", PARAPHRASED_ATTACKS, True),
        ("ordinary", ORDINARY_TEXT, False),
        ("awkward", AWKWARD_BENIGN, False),
    ]
    for group, texts, attack in sets:
        for index, text in enumerate(texts):
            items.append(
                ScanItem(
                    id=f"lab-{group}-{index:02d}",
                    dataset="lab",
                    text=text,
                    attack=attack,
                    source="text",
                )
            )
    return items


# ---- Running a config -----------------------------------------------------------------------


def settings_for(config: ScanConfig, root: Path) -> Settings:
    options: dict[str, Any] = {
        "db_path": root / f"{config.name}.db",
        "admin_token_path": root / "admin_token",
        "enabled_layers": config.layers,
        "judge_mode": config.judge_mode,
    }
    if config.classifier_model:
        # The fallback is the same model, so a missing export fails loudly instead of quietly
        # scoring with a different classifier.
        options["classifier_model"] = config.classifier_model
        options["fallback_classifier_model"] = config.classifier_model
    if config.score_only:
        options["classifier_threshold"] = 0.0
    elif config.classifier_threshold is not None:
        options["classifier_threshold"] = config.classifier_threshold
    return Settings(_env_file=None, **options)  # type: ignore[call-arg]


def _layer_errors(body: dict[str, Any]) -> str | None:
    """A layer that errored made the policy fail closed, so the decision isn't a real verdict:
    the item is counted as an error, not as a catch or a false alarm."""
    layers = body.get("layers_run", {})
    failed = sorted(name for name, status in layers.items() if status == "error")
    return f"layer error: {', '.join(failed)}" if failed else None


def _result(item: ScanItem, body: dict[str, Any], seconds: float, score_only: bool) -> ItemResult:
    findings = body.get("findings", [])
    l1 = [float(finding["score"]) for finding in findings if finding["layer"] == "L1"]
    return ItemResult(
        id=item.id,
        dataset=item.dataset,
        attack=item.attack,
        # With L1's threshold at 0 every item is flagged, so a score-only decision means nothing.
        decision=None if score_only else Decision(body["decision"]),
        risk=None if score_only else float(body["risk_score"]),
        l1_score=max(l1) if l1 else (0.0 if "L1" in body.get("layers_run", {}) else None),
        latency_ms=float(body.get("total_latency_ms") or seconds * 1000),
        rules=sorted({finding["rule_id"] for finding in findings}),
        error=_layer_errors(body),
    )


def run_config(
    config: ScanConfig,
    items: Sequence[ScanItem],
    progress: Callable[[str], None] = print,
) -> list[ItemResult]:
    """Every item through POST /v1/scan, each in its own session so nothing carries over."""
    results: list[ItemResult] = []
    with tempfile.TemporaryDirectory() as folder:
        settings = settings_for(config, Path(folder))
        with TestClient(create_app(settings), base_url=BASE_URL) as client:
            for index, item in enumerate(items, start=1):
                started = perf_counter()
                payload = {
                    "items": [{"kind": "text", "data": item.text, "source": item.source}],
                    "user_task": TASK,
                }
                response = client.post("/v1/scan", json=payload)
                seconds = perf_counter() - started
                if response.status_code != 200:
                    results.append(
                        ItemResult(
                            id=item.id,
                            dataset=item.dataset,
                            attack=item.attack,
                            error=f"HTTP {response.status_code}",
                        )
                    )
                else:
                    results.append(_result(item, response.json(), seconds, config.score_only))
                if index % 50 == 0 or index == len(items):
                    progress(f"  {config.name}: {index}/{len(items)}")
    gc.collect()  # let the classifier go before the next config loads its own
    return results


def models_used(results: Sequence[ItemResult]) -> list[str]:
    """Rule ids name the classifier that scored, which proves which model really ran."""
    return sorted(
        {rule for result in results for rule in result.rules if rule.startswith("L1.CLASSIFIER.")}
    )


def judge_band_items(results: Sequence[ItemResult], band: tuple[float, float]) -> int:
    """How many items the judge would see: the full pipeline's risk inside the uncertain band."""
    low, high = band
    return sum(1 for result in results if result.risk is not None and low <= result.risk <= high)
