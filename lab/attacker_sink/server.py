"""Records everything sent to it. Run it with `uv run python -m lab.attacker_sink.server`.

Results come from this log, so the log must be trustworthy: only DELETE clears it, and no lab tool
can send a DELETE, so a hijacked agent can't wipe the evidence of its own attack.
"""

from collections import deque

import uvicorn
from fastapi import FastAPI, Request
from pydantic import AwareDatetime, Field

from promptshield.config import get_settings
from promptshield.models import Schema, new_id, utc_now

MAX_CAPTURES = 1000
MAX_BODY_BYTES = 65536
RECORDED_METHODS = ["GET", "POST", "PUT", "PATCH"]


class Capture(Schema):
    id: str = Field(default_factory=new_id)
    ts: AwareDatetime = Field(default_factory=utc_now)
    method: str
    path: str
    query: str
    body: str


def create_app() -> FastAPI:
    app = FastAPI(title="Attacker sink", docs_url=None, redoc_url=None, openapi_url=None)
    captures: deque[Capture] = deque(maxlen=MAX_CAPTURES)

    @app.get("/captured")
    async def captured() -> list[Capture]:
        return list(captures)

    @app.delete("/captured")
    async def clear() -> dict[str, str]:
        captures.clear()
        return {"status": "cleared"}

    @app.api_route("/{path:path}", methods=RECORDED_METHODS)
    async def record(path: str, request: Request) -> dict[str, str]:
        body = await request.body()
        captures.append(
            Capture(
                method=request.method,
                path=f"/{path}",
                query=request.url.query,
                body=body[:MAX_BODY_BYTES].decode("utf-8", errors="replace"),
            )
        )
        return {"status": "ok"}

    return app


def main() -> None:
    settings = get_settings()
    uvicorn.run(create_app(), host=settings.host, port=settings.sink_port)


if __name__ == "__main__":
    main()
