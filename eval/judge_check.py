"""Does the L3 judge separate attacks from benign text? Run before trusting it (D027).

    uv run python -m eval.judge_check --model qwen3:1.7b --model qwen3:4b-instruct

Short texts are judged with no task. Lab pages go through L0 and L2 first, as in the shield, and
are judged with a summary task. Results go to eval/reports/judge_check_<time>.json.
"""

import argparse
import asyncio
import json
import statistics
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from lab.attack_site.build import PAGES, build_site
from promptshield.config import Settings, get_settings
from promptshield.layers.base import ScanContext
from promptshield.layers.l0_normalize import NormalizeLayer
from promptshield.layers.l2_hidden import HiddenContentLayer
from promptshield.layers.l3_judge import MALFORMED_RULE, MALICIOUS_RULE, JudgeLayer
from promptshield.models import ContentItem, Schema, Segment, SessionInfo
from promptshield.provenance import git_description, machine_description
from tests.fixtures.wording import (
    AWKWARD_BENIGN,
    COMMON_ATTACKS,
    ORDINARY_TEXT,
    PARAPHRASED_ATTACKS,
)

PAGE_TASK = "Summarize this web page for me."


class Case(Schema):
    group: str
    name: str
    attack: bool
    task: str | None = None
    segments: list[Segment]


class Result(Schema):
    model: str
    group: str
    name: str
    attack: bool
    verdict: str
    seconds: float
    evidence: str


def text_cases() -> list[Case]:
    sets = [
        ("common attacks", COMMON_ATTACKS, True),
        ("paraphrased attacks", PARAPHRASED_ATTACKS, True),
        ("ordinary text", ORDINARY_TEXT, False),
        ("awkward benign", AWKWARD_BENIGN, False),
    ]
    return [
        Case(
            group=group,
            name=text[:50],
            attack=attack,
            segments=[Segment(text=text, origin="visible")],
        )
        for group, texts, attack in sets
        for text in texts
    ]


async def page_cases(settings: Settings) -> list[Case]:
    normalize, hidden = NormalizeLayer(settings), HiddenContentLayer()
    cases: list[Case] = []
    with tempfile.TemporaryDirectory() as folder:
        site = Path(folder)
        build_site(site, settings.sink_port)
        for page in PAGES:
            html = (site / page.filename).read_text(encoding="utf-8")
            ctx = ScanContext(
                session=SessionInfo(user_task=PAGE_TASK),
                items=[ContentItem(kind="text", data=html, source=page.filename)],
            )
            await normalize.scan(ctx)
            await hidden.scan(ctx)
            cases.append(
                Case(
                    group="lab pages",
                    name=page.id,
                    attack=page.id.startswith("A"),
                    task=PAGE_TASK,
                    segments=ctx.segments,
                )
            )
    return cases


async def judge_all(model: str, cases: Sequence[Case], settings: Settings) -> list[Result]:
    layer = JudgeLayer(settings.model_copy(update={"judge_model": model}))
    results: list[Result] = []
    for case in cases:
        ctx = ScanContext(session=SessionInfo(user_task=case.task), segments=case.segments)
        started = perf_counter()
        [finding] = await layer.scan(ctx)
        verdict = {MALICIOUS_RULE: "malicious", MALFORMED_RULE: "malformed"}.get(
            finding.rule_id, "benign"
        )
        results.append(
            Result(
                model=model,
                group=case.group,
                name=case.name,
                attack=case.attack,
                verdict=verdict,
                seconds=perf_counter() - started,
                evidence=finding.evidence,
            )
        )
        print(f"  {model:18} {case.group:20} {case.name[:30]:30} {verdict}", flush=True)
    return results


def summary(results: Sequence[Result]) -> list[str]:
    lines: list[str] = []
    for model in dict.fromkeys(result.model for result in results):
        mine = [result for result in results if result.model == model]
        lines.append(f"{model}: p50 {statistics.median(r.seconds for r in mine):.1f} s per call")
        for group in dict.fromkeys(result.group for result in mine):
            rows = [result for result in mine if result.group == group]
            for attack in (True, False):
                part = [row for row in rows if row.attack is attack]
                if not part:
                    continue
                flagged = sum(row.verdict == "malicious" for row in part)
                malformed = sum(row.verdict == "malformed" for row in part)
                label = "caught" if attack else "flagged"
                lines.append(
                    f"  {group:20} {'attacks' if attack else 'benign':8} {label} "
                    f"{flagged}/{len(part)}, malformed {malformed}"
                )
    return lines


async def main(models: Sequence[str]) -> None:
    # Windows consoles default to cp1252, which can't print the Hindi, Arabic or Chinese cases.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    settings = get_settings()
    cases = [*text_cases(), *await page_cases(settings)]
    results: list[Result] = []
    for model in models:
        results.extend(await judge_all(model, cases, settings))
    lines = summary(results)
    print("\n".join(lines))
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M")
    path = settings.reports_dir / f"judge_check_{stamp}.json"
    record = {
        "date": stamp,
        "git": git_description(),
        "machine": machine_description(),
        "num_ctx": settings.num_ctx,
        "think": settings.think,
        "num_predict": settings.judge_num_predict,
        "summary": lines,
        "results": [result.model_dump() for result in results],
    }
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check whether the L3 judge separates attacks.")
    parser.add_argument("--model", action="append", required=True)
    asyncio.run(main(parser.parse_args().model))
