"""The FastAPI app. Run it with `uv run python -m promptshield.api.server`."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from promptshield.api.auth import TOKEN_HEADER, admin_token
from promptshield.api.routes import (
    approvals,
    bench,
    config,
    events,
    guard,
    health,
    lab,
    scan,
    stats,
    stream,
)
from promptshield.api.routes import policy as policy_routes
from promptshield.api.routes import registry as registry_routes
from promptshield.api.routes import sessions as session_routes
from promptshield.api.state import AppState
from promptshield.api.web import dashboard_built, mount_dashboard
from promptshield.approvals import ApprovalQueue
from promptshield.config import Settings, get_settings
from promptshield.events import EventBus
from promptshield.gateway.core import Gateway, GatewayServices
from promptshield.gateway.server import (
    HttpGateway,
    MountedGateway,
    build_server,
    connect_upstreams,
)
from promptshield.layers.canary import CanaryStore
from promptshield.layers.defaults import default_registry
from promptshield.layers.l4_action_guard import ActionGuard, Dlp
from promptshield.logs import configure_logging
from promptshield.pipeline import ContentPipeline, LayerRegistry
from promptshield.policy.engine import PolicyEngine
from promptshield.policy.schema import load_policy
from promptshield.redact import Redactor
from promptshield.registry_guard import RegistryGuard
from promptshield.sanitize import Sanitizer
from promptshield.sessions import SessionStore
from promptshield.shield import Shield
from promptshield.storage.db import Database
from promptshield.taint import TaintSettings

logger = structlog.get_logger(__name__)

# Stops DNS rebinding, where a malicious site points its own name at 127.0.0.1.
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]


def _error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or {}}}


async def _on_validation_error(_: Request, error: Exception) -> JSONResponse:
    """Report where the problem is, never the input: it may hold a secret or attack text."""
    assert isinstance(error, RequestValidationError)
    fields = [
        {"field": ".".join(str(part) for part in item["loc"]), "problem": item["type"]}
        for item in error.errors()
    ]
    return JSONResponse(
        status_code=422,
        content=_error_body("validation_error", "Invalid request", {"fields": fields}),
    )


async def _on_http_error(_: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, HTTPException)
    return JSONResponse(
        status_code=error.status_code,
        content=_error_body(f"http_{error.status_code}", str(error.detail)),
        headers=error.headers,
    )


async def _on_unexpected_error(_: Request, error: Exception) -> JSONResponse:
    logger.error("request_failed", error=type(error).__name__)
    return JSONResponse(
        status_code=500, content=_error_body("internal_error", "Something went wrong")
    )


def build_state(
    settings: Settings, registry: LayerRegistry, canaries: CanaryStore, redactor: Redactor
) -> AppState:
    database = Database(settings.db_path, redactor)
    engine = PolicyEngine(load_policy(settings.policy_path))
    pipeline = ContentPipeline.from_settings(settings, registry, engine.should_judge)
    # Same registry, so the re-scan reuses the loaded models. No judge in the re-scan (shield.py).
    rescan = ContentPipeline(
        registry,
        [name for name in settings.enabled_layers if name != "L3"],
        judge_mode="off",
        layer_timeout_seconds=settings.layer_timeout_seconds,
    )
    sanitizer = Sanitizer(settings, lambda: engine.policy.sanitize)
    sessions = SessionStore(
        settings.max_sessions,
        TaintSettings(settings.taint_shingle_words, settings.taint_max_fingerprints),
    )
    bus = EventBus(database, redactor, settings.event_queue_size)
    queue = ApprovalQueue(database, bus, engine)
    queue.expire_orphans()
    return AppState(
        settings=settings,
        database=database,
        bus=bus,
        engine=engine,
        registry=registry,
        pipeline=pipeline,
        shield=Shield(pipeline, rescan, engine, sanitizer),
        sessions=sessions,
        canaries=canaries,
        guard=ActionGuard(settings, engine, sessions, canaries, Dlp(settings)),
        approvals=queue,
        registry_guard=RegistryGuard(
            pipeline, engine, database, bus, enabled="REGISTRY" in settings.enabled_layers
        ),
        admin_token=admin_token(settings),
        redactor=redactor,
    )


def gateway_services(state: AppState) -> GatewayServices:
    return GatewayServices(
        engine=state.engine,
        guard=state.guard,
        approvals=state.approvals,
        shield=state.shield,
        sessions=state.sessions,
        bus=state.bus,
        database=state.database,
        registry=state.registry_guard,
    )


def create_app(settings: Settings | None = None, registry: LayerRegistry | None = None) -> FastAPI:
    """Build the app. Until L1 is registered, scans fail closed because it's a required layer."""
    active_settings = settings or get_settings()
    # One redactor for the whole app, so canaries registered later are hidden everywhere.
    redactor = Redactor(active_settings.event_text_limit)
    canaries = CanaryStore(redactor)
    active_registry = registry or default_registry(active_settings, canaries)

    mounted = MountedGateway()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(active_settings.log_format)
        state = build_state(active_settings, active_registry, canaries, redactor)
        app.state.shield = state
        # Warm up in the background: loading the classifier and asking Ollama to load the judge can
        # take a minute, and MCP apps give up on a server that isn't answering by then. A scan that
        # arrives first loads what it needs itself (the classifier load is locked).
        warming = asyncio.create_task(state.pipeline.warmup())
        async with connect_upstreams(active_settings.gateway_upstreams) as upstreams:
            gateway = Gateway(
                gateway_services(state),
                upstreams,
                call_timeout_seconds=active_settings.gateway_call_timeout_seconds,
            )
            app.state.gateway = gateway
            http = HttpGateway(build_server(gateway))
            async with http.run():
                mounted.attach(http)
                try:
                    yield
                finally:
                    mounted.attach(None)
        warming.cancel()
        state.database.close()

    app = FastAPI(title="PromptShield", version="0.1.0", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=stream.allowed_origins(
            active_settings.dashboard_port, active_settings.api_port
        ),
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["Content-Type", TOKEN_HEADER],
    )
    app.add_exception_handler(RequestValidationError, _on_validation_error)
    app.add_exception_handler(HTTPException, _on_http_error)
    app.add_exception_handler(Exception, _on_unexpected_error)
    app.include_router(health.router)
    app.include_router(scan.router)
    app.include_router(guard.router)
    app.include_router(approvals.router)
    app.include_router(registry_routes.router)
    app.include_router(lab.router)
    app.include_router(events.router)
    app.include_router(config.router)
    app.include_router(stats.router)
    app.include_router(session_routes.router)
    app.include_router(policy_routes.router)
    app.include_router(bench.router)
    app.include_router(stream.router)
    app.mount("/mcp", mounted)
    if dashboard_built():
        mount_dashboard(app)
    return app


def main() -> None:
    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.api_port)


if __name__ == "__main__":
    main()
