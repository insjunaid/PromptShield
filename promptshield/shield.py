"""One inbound inspection: scan, decide, and sanitize if that's the verdict.

A BLOCK can become SANITIZE only if the stripped content scans clean (POLICY_ENGINE §5). That
re-scan reads the stripped text without spotlighting, and without the judge: the judge is slow, and
a clean result must come from the detectors alone.
"""

import asyncio

from promptshield.layers.base import ScanContext
from promptshield.models import Decision, Verdict
from promptshield.pipeline import ContentPipeline
from promptshield.policy.engine import PolicyEngine
from promptshield.sanitize import Sanitizer, Stripped


class Shield:
    def __init__(
        self,
        pipeline: ContentPipeline,
        rescan_pipeline: ContentPipeline,
        engine: PolicyEngine,
        sanitizer: Sanitizer,
    ) -> None:
        self._pipeline = pipeline
        self._rescan = rescan_pipeline
        self._engine = engine
        self._sanitizer = sanitizer

    async def inspect(self, ctx: ScanContext) -> Verdict:
        result = await self._pipeline.scan(ctx)
        stripped: Stripped | None = None
        rescan = None
        if self._engine.wants_rescan(result):
            stripped = await asyncio.to_thread(self._sanitizer.strip, ctx.items, result.findings)
            rescan = await self._rescan.scan(ScanContext(session=ctx.session, items=stripped.items))
        verdict = self._engine.decide_inbound(result, rescan)
        if verdict.decision is not Decision.SANITIZE:
            return verdict
        if stripped is None:
            stripped = await asyncio.to_thread(self._sanitizer.strip, ctx.items, result.findings)
        return verdict.model_copy(update={"sanitized_items": self._sanitizer.spotlight(stripped)})
