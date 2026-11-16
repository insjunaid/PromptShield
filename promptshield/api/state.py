"""Objects shared by every request, built once at startup."""

from dataclasses import dataclass

from pydantic import SecretStr
from starlette.requests import HTTPConnection

from promptshield.approvals import ApprovalQueue
from promptshield.config import Settings
from promptshield.events import EventBus
from promptshield.layers.canary import CanaryStore
from promptshield.layers.l4_action_guard import ActionGuard
from promptshield.pipeline import ContentPipeline, LayerRegistry
from promptshield.policy.engine import PolicyEngine
from promptshield.redact import Redactor
from promptshield.registry_guard import RegistryGuard
from promptshield.sessions import SessionStore
from promptshield.shield import Shield
from promptshield.storage.db import Database


@dataclass
class AppState:
    settings: Settings
    database: Database
    bus: EventBus
    engine: PolicyEngine
    registry: LayerRegistry
    pipeline: ContentPipeline
    shield: Shield
    sessions: SessionStore
    canaries: CanaryStore
    guard: ActionGuard
    approvals: ApprovalQueue
    registry_guard: RegistryGuard
    admin_token: SecretStr
    redactor: Redactor


def get_state(connection: HTTPConnection) -> AppState:
    """Works for both HTTP requests and WebSockets."""
    state: AppState = connection.app.state.shield
    return state
