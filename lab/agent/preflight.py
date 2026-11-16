"""Checks the agent model before a run, so a bad setup can't quietly skew the results.

An empty `thinking` field proves nothing: the `qwen3:4b` build moved its reasoning into the reply
instead. So this also reads the reply itself and counts its tokens.
"""

import httpx

from promptshield.config import Settings

REASONING_MARKERS = ("hmm", "the user", "let me", "i need to", "okay,", "<think>", "wait,")
PROBE_PROMPT = "Reply with the single word OK."
PROBE_MAX_TOKENS = 40
PROBE_EXPECTED_MAX_TOKENS = 10
TIMEOUT_SECONDS = 120.0


class ModelNotReady(RuntimeError):
    """The model can't produce a trustworthy run."""


def _check_build(model: str, details: dict[str, object]) -> None:
    capabilities = details.get("capabilities") or []
    if not isinstance(capabilities, list) or "tools" not in capabilities:
        raise ModelNotReady(f"{model} does not support tool calling")
    info = details.get("model_info")
    finetune = info.get("general.finetune") if isinstance(info, dict) else None
    if isinstance(finetune, str) and finetune.lower() == "thinking":
        raise ModelNotReady(f"{model} is a thinking-only build, so thinking can't be turned off")


def _check_reply(model: str, result: dict[str, object]) -> None:
    message = result.get("message")
    if not isinstance(message, dict):
        raise ModelNotReady(f"{model} returned no message")
    content = str(message.get("content") or "").lower()
    if message.get("thinking"):
        raise ModelNotReady(f"{model} is still thinking")
    if any(marker in content for marker in REASONING_MARKERS):
        raise ModelNotReady(f"{model} put reasoning in its reply")
    tokens = result.get("eval_count")
    if isinstance(tokens, int) and tokens > PROBE_EXPECTED_MAX_TOKENS:
        raise ModelNotReady(f"{model} used {tokens} tokens to answer a one-word question")


async def check_agent_model(
    settings: Settings, transport: httpx.AsyncBaseTransport | None = None
) -> None:
    """Raise ModelNotReady unless the agent model can call tools with thinking really off."""
    model = settings.agent_model
    body = {
        "model": model,
        "think": settings.think,
        "stream": False,
        "options": {
            "num_ctx": settings.num_ctx,
            "num_predict": PROBE_MAX_TOKENS,
            "temperature": 0,
        },
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
    }
    async with httpx.AsyncClient(
        base_url=settings.ollama_url, transport=transport, timeout=TIMEOUT_SECONDS, trust_env=False
    ) as client:
        try:
            show = await client.post("/api/show", json={"model": model})
            if show.status_code != 200:
                raise ModelNotReady(f"{model} is not available in Ollama")
            _check_build(model, show.json())
            reply = await client.post("/api/chat", json=body)
        except httpx.HTTPError as error:
            raise ModelNotReady("Ollama is not reachable") from error
    if reply.status_code != 200:
        raise ModelNotReady(f"{model} could not answer (HTTP {reply.status_code})")
    _check_reply(model, reply.json())
