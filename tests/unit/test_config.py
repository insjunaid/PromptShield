"""Settings enforce the project's safety rules, and must never leak the token."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from promptshield.config import REPO_ROOT, Settings, get_settings

FAKE_TOKEN = "hf_fakefakefakefakefakefakefake"
OVERRIDES = ("HF_TOKEN", "OLLAMA_URL")


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's real environment out of these tests."""
    for name in OVERRIDES:
        monkeypatch.delenv(name, raising=False)


def load(**values: Any) -> Settings:
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


def test_defaults_match_the_documented_setup() -> None:
    settings = load()
    assert settings.host == "127.0.0.1"
    assert settings.api_port == 8000
    assert settings.gateway_port == 8765
    assert settings.num_ctx == 8192
    assert settings.think is False
    assert settings.agent_model == "qwen3:4b-instruct"
    assert settings.judge_model == "qwen3:4b-instruct"


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com"])
def test_non_loopback_host_is_refused(host: str) -> None:
    with pytest.raises(ValidationError, match="loopback"):
        load(host=host)


@pytest.mark.parametrize("url", ["http://10.0.0.5:11434", "https://ollama.example"])
def test_remote_ollama_is_refused(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("OLLAMA_URL", url)
    with pytest.raises(ValidationError, match="loopback"):
        load()


def test_local_ollama_url_loses_its_trailing_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:11434/")
    assert load().ollama_url == "http://127.0.0.1:11434"


def test_duplicate_ports_are_refused() -> None:
    with pytest.raises(ValidationError, match="unique"):
        load(sink_port=8000)


def test_port_out_of_range_is_refused() -> None:
    with pytest.raises(ValidationError):
        load(api_port=70000)


def test_small_context_window_is_refused() -> None:
    with pytest.raises(ValidationError):
        load(num_ctx=512)


def test_prefixed_environment_overrides_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROMPTSHIELD_AGENT_MODEL", "other:model")
    monkeypatch.setenv("PROMPTSHIELD_NUM_CTX", "4096")
    settings = load()
    assert settings.agent_model == "other:model"
    assert settings.num_ctx == 4096


def test_env_file_is_read(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"HF_TOKEN={FAKE_TOKEN}\nUNRELATED=1\n", encoding="utf-8")
    settings = Settings(_env_file=env_file)  # type: ignore[call-arg]
    assert settings.hf_token is not None
    assert settings.hf_token.get_secret_value() == FAKE_TOKEN


def test_token_never_appears_in_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HF_TOKEN", FAKE_TOKEN)
    settings = load()
    assert FAKE_TOKEN not in repr(settings)
    assert FAKE_TOKEN not in str(settings)
    assert FAKE_TOKEN not in settings.model_dump_json()


def test_empty_token_means_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HF_TOKEN", "")
    assert load().hf_token is None


def test_relative_paths_resolve_from_the_repo_root() -> None:
    assert load().db_path == REPO_ROOT / "data" / "promptshield.db"


def test_absolute_paths_are_kept(tmp_path: Path) -> None:
    assert load(db_path=tmp_path / "x.db").db_path == tmp_path / "x.db"


def test_unknown_layer_is_refused() -> None:
    with pytest.raises(ValidationError):
        load(enabled_layers=["L9"])


def test_settings_are_loaded_once() -> None:
    assert get_settings() is get_settings()


@pytest.mark.parametrize("path", [".env.example", "scripts/check.ps1", "scripts/check.sh"])
def test_scripts_use_the_same_default_models(path: str) -> None:
    """The check scripts can't import this module, so guard against the defaults drifting."""
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    settings = load()
    assert settings.agent_model in text
    assert settings.judge_model in text
