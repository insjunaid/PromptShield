"""Infrastructure settings: ports, paths, model ids and modes.

Decision thresholds live in the policy YAML, not here. The checks below enforce the project's safety
rules at startup, so a bad override stops the process instead of exposing the lab.
"""

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from promptshield.models import LayerName

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parent
HOME_ENV = "PROMPTSHIELD_HOME"
SERVERS_FILE = "servers.json"


def is_source_checkout(root: Path = REPO_ROOT) -> bool:
    """A clone of the repo, as opposed to an installed package in site-packages."""
    return (root / "pyproject.toml").is_file() and (root / "lab").is_dir()


def default_home() -> Path:
    """Where data, models, `.env` and the server list live. A clone keeps using the repo folder,
    so nothing changes for development; an installed copy uses ~/.promptshield."""
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return REPO_ROOT if is_source_checkout() else Path.home() / ".promptshield"


HOME = default_home()


class UpstreamServer(BaseModel):
    """A tool server the gateway starts over stdio and stands in front of."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    command: str = Field(min_length=1)
    args: list[str] = Field(default_factory=list)


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class Settings(BaseSettings):
    """Loaded from the environment and `.env`. Most names take the PROMPTSHIELD_ prefix."""

    model_config = SettingsConfigDict(
        env_prefix="PROMPTSHIELD_",
        env_file=HOME / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Network. Every service binds to loopback only.
    host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    gateway_port: int = Field(default=8765, ge=1, le=65535)
    attack_site_port: int = Field(default=8081, ge=1, le=65535)
    sink_port: int = Field(default=9999, ge=1, le=65535)
    dashboard_port: int = Field(default=5173, ge=1, le=65535)

    # Local LLMs through the Ollama HTTP API.
    ollama_url: str = Field(default="http://localhost:11434", validation_alias="OLLAMA_URL")
    agent_model: str = "qwen3:4b-instruct"
    # The agent model doubles as judge (Junaid, 2026-11-11, D049): it flagged no benign text in
    # D048, where the 1.7B model flagged 5 of 19.
    judge_model: str = "qwen3:4b-instruct"
    num_ctx: int = Field(default=8192, ge=2048)
    think: bool = False
    agent_num_predict: int = Field(default=512, ge=16)
    agent_max_tool_rounds: int = Field(default=8, ge=1)
    scenario_timeout_seconds: float = Field(default=300.0, gt=0)
    # Room for a one-sentence reason before the verdict, which D027 suggested trying.
    judge_num_predict: int = Field(default=160, ge=16)
    judge_timeout_seconds: float = Field(default=50.0, gt=0)
    judge_load_seconds: float = Field(default=180.0, gt=0)  # loading a model cold at startup
    judge_max_chars: int = Field(default=6000, ge=200)
    # Matches Ollama's default, because the judge shares the agent's model: a shorter value would
    # unload the agent between steps.
    judge_keep_alive: str = "5m"
    # Only in the uncertain band. The judge can raise risk but not lower it (policy, D049).
    judge_mode: Literal["off", "uncertain", "always"] = "uncertain"

    # L1 classifiers.
    classifier_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    fast_classifier_model: str = "meta-llama/Llama-Prompt-Guard-2-22M"
    fallback_classifier_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    hf_token: SecretStr | None = Field(default=None, validation_alias="HF_TOKEN")
    # INT8 lost attacks on every model tested (D046), so full precision is the default.
    classifier_precision: Literal["int8", "fp32"] = "fp32"
    classifier_threads: int = Field(default=4, ge=1)
    classifier_batch_size: int = Field(default=8, ge=1)
    # Scores under this aren't reported. Calibrated in P7.1 on deepset/prompt-injections train: the
    # highest recall with FPR <= 5% (eval/reports/scan_20261114_1552.md, D065). Policy thresholds
    # still decide: a lone weak hit adds risk but stays under the sanitize line.
    classifier_threshold: float = Field(default=0.10, ge=0, le=1)
    # The fallback (ProtectAI) when it is the classifier that ran. 0.10 was calibrated for Prompt
    # Guard 2 only; 0.50 is where the scan report measured the fallback (not calibrated).
    fallback_classifier_threshold: float = Field(default=0.50, ge=0, le=1)
    # The fallback model as a second opinion on Latin-script text (Junaid, 2026-11-11, option B).
    # Off until P7 measures its false positives on public benign data. Costs about 0.9 GB.
    classifier_second_opinion: bool = False

    # Pipeline.
    # L4 (action guard) and REGISTRY (tool definition guard) are switches too, for the ablation
    # (P7.3); turning either off is for measurement, not for use.
    enabled_layers: list[LayerName] = ["L0", "L2", "L1", "CANARY", "L3", "L4", "REGISTRY"]
    layer_timeout_seconds: float = Field(default=60.0, gt=0)

    # L0. Windows match Prompt Guard 2's 512-token context.
    chunk_max_tokens: int = Field(default=512, ge=16)
    chunk_overlap_tokens: int = Field(default=64, ge=0)
    chunk_chars_per_token: int = Field(default=2, ge=1)
    decode_min_length: int = Field(default=24, ge=8)
    decode_printable_ratio: float = Field(default=0.85, gt=0, le=1)
    decode_max_depth: int = Field(default=2, ge=1)
    decode_max_payloads: int = Field(default=64, ge=1)
    css_max_selector_checks: int = Field(default=300_000, ge=1)
    css_min_contrast: float = Field(default=1.2, ge=1)
    css_tiny_font_px: float = Field(default=2.0, ge=0)
    css_offscreen_px: float = Field(default=500.0, gt=0)

    # OCR. The timeout is under the layer timeout, so a stuck worker shows up as an OCR failure.
    ocr_timeout_seconds: float = Field(default=45.0, gt=0)
    ocr_idle_seconds: float = Field(default=120.0, gt=0)
    ocr_max_image_bytes: int = Field(default=10_000_000, ge=1)
    ocr_max_pixels: int = Field(default=25_000_000, ge=1)
    ocr_max_images: int = Field(default=8, ge=1)

    # Paths. Relative values resolve from the home folder (the repo in a clone, ~/.promptshield when
    # installed), so any working directory behaves the same. The default policy ships inside the
    # package.
    db_path: Path = Path("data/promptshield.db")
    policy_path: Path = PACKAGE_DIR / "policy" / "default.yaml"
    lab_runs_dir: Path = Path("lab/runs")
    scenarios_dir: Path = Path("lab/scenarios")
    attack_site_dir: Path = Path("lab/attack_site/public")
    reports_dir: Path = Path("eval/reports")
    models_dir: Path = Path("models")

    # Sessions and taint. Kept in memory only (sessions.py).
    max_sessions: int = Field(default=1000, ge=1)
    taint_shingle_words: int = Field(default=5, ge=2)
    taint_max_fingerprints: int = Field(default=50_000, ge=100)

    # L4 action guard.
    dlp_min_entropy: float = Field(default=4.0, gt=0)
    # Presidio adds about 400 MB and a 12 s load (D053). Needs `uv sync --group pii`.
    dlp_presidio: bool = False
    # Asks the judge model whether an egress or write call fits the user's task. Optional (spec).
    task_alignment: bool = False

    # Admin token for mutating routes. Unset means a fresh one per start, written to the file.
    admin_token: SecretStr | None = None
    admin_token_path: Path = Path("data/admin_token")

    # Gateway. Upstream names are the `server` part of policy keys, such as `files.read_file`.
    # Set here (JSON), or kept by `promptshield servers add` in servers.json in the home folder.
    gateway_upstreams: list[UpstreamServer] = Field(default_factory=list)
    servers_file: Path = Path(SERVERS_FILE)
    gateway_call_timeout_seconds: float = Field(default=120.0, gt=0)

    # Events.
    event_queue_size: int = Field(default=1000, ge=1)
    event_text_limit: int = Field(default=20000, ge=100)

    # Logging.
    log_format: Literal["dev", "json"] = "dev"

    @field_validator("host")
    @classmethod
    def require_loopback_host(cls, value: str) -> str:
        if value not in LOOPBACK_HOSTS:
            raise ValueError(f"host must be loopback, got {value!r}")
        return value

    @field_validator("ollama_url")
    @classmethod
    def require_local_ollama(cls, value: str) -> str:
        """Scanned content goes to the judge, so a remote server would send it off the machine."""
        if urlsplit(value).hostname not in LOOPBACK_HOSTS:
            raise ValueError("ollama_url must point to a loopback host")
        return value.rstrip("/")

    @field_validator("hf_token")
    @classmethod
    def treat_empty_token_as_missing(cls, value: SecretStr | None) -> SecretStr | None:
        """`.env.example` ships `HF_TOKEN=`, which must mean "no token", not an empty one."""
        return value if value and value.get_secret_value() else None

    @field_validator(
        "db_path",
        "policy_path",
        "lab_runs_dir",
        "scenarios_dir",
        "attack_site_dir",
        "reports_dir",
        "models_dir",
        "admin_token_path",
        "servers_file",
    )
    @classmethod
    def resolve_from_home(cls, value: Path) -> Path:
        return value if value.is_absolute() else HOME / value

    @model_validator(mode="after")
    def load_servers_file(self) -> Self:
        """Servers set in the environment win; otherwise the list `promptshield servers` keeps."""
        if not self.gateway_upstreams and self.servers_file.is_file():
            entries = json.loads(self.servers_file.read_text(encoding="utf-8"))
            self.gateway_upstreams = [UpstreamServer.model_validate(entry) for entry in entries]
        return self

    @model_validator(mode="after")
    def require_unique_ports(self) -> Self:
        ports = [
            self.api_port,
            self.gateway_port,
            self.attack_site_port,
            self.sink_port,
            self.dashboard_port,
        ]
        if len(set(ports)) != len(ports):
            raise ValueError("service ports must be unique")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the shared settings, read once per process."""
    return Settings()
