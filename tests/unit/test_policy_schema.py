"""A bad policy must be refused, because it can arrive through the API."""

import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from promptshield.config import REPO_ROOT
from promptshield.models import Decision
from promptshield.policy.schema import Policy, load_policy, parse_policy

DEFAULT_POLICY = REPO_ROOT / "promptshield" / "policy" / "default.yaml"


def test_default_policy_loads() -> None:
    policy = load_policy(DEFAULT_POLICY)
    assert policy.mode == "enforce"
    assert policy.force["CANARY.tripped"] is Decision.BLOCK
    assert policy.tools["http.http_post"].tool_class == "egress"
    assert policy.tools["files.delete_file"].require_approval is True


def test_default_policy_fails_closed() -> None:
    policy = load_policy(DEFAULT_POLICY)
    assert policy.fail_mode.content_scan == "closed"
    assert policy.fail_mode.action_guard == "closed"
    assert policy.default_tool_class == "egress"


def test_docs_show_the_real_default_policy() -> None:
    """The design notes are private working files, not published: this runs only where they are."""
    path = REPO_ROOT / "docs" / "POLICY_ENGINE.md"
    if not path.exists():
        pytest.skip("design notes aren't in this checkout")
    doc = path.read_text(encoding="utf-8")
    block = re.search(r"```yaml\n(.*?)```", doc, re.DOTALL)
    assert block is not None
    assert yaml.safe_load(block.group(1)) == yaml.safe_load(
        DEFAULT_POLICY.read_text(encoding="utf-8")
    )


def test_empty_policy_uses_safe_defaults() -> None:
    policy = Policy()
    assert policy.fail_mode.action_guard == "closed"
    assert policy.default_tool_class == "egress"


@pytest.mark.parametrize(
    "text",
    [
        "version: 2",
        "mode: disabled",
        "surprise: true",
        "thresholds: {sanitize: 0.8, block: 0.5}",
        "thresholds: {sanitize: 0.75, block: 0.75}",
        "thresholds: {block: 1.5}",
        "thresholds: {judge_band: [0.8, 0.3]}",
        "thresholds: {judge_band: [0.3, 1.2]}",
        "weights: {L1: -1}",
        "weights: {hidden_origin_boost: 0.5}",
        "force: {CANARY.tripped: ALLOW}",
        "force: {CANARY.tripped: REQUIRE_APPROVAL}",
        "tools: {send_email: {class: egress}}",
        "tools: {mail.send_email: {class: magic}}",
        "egress: {allow_hosts: [localhost]}",
        "egress: {allow_hosts: ['127.0.0.1']}",
        "egress: {allow_hosts: ['http://company.example']}",
        "egress: {deny_hosts: [localhost]}",
        "egress: {unknown_destination: ALLOW}",
        "approvals: {on_timeout: ALLOW}",
        "approvals: {timeout_seconds: 0}",
        "sanitize: {marker: ''}",
    ],
)
def test_invalid_policies_are_refused(text: str) -> None:
    with pytest.raises(ValidationError):
        parse_policy(text)


def test_unsafe_yaml_tags_are_refused() -> None:
    with pytest.raises(yaml.YAMLError):
        parse_policy("mode: !!python/object/apply:os.system ['echo hacked']")


def test_policy_round_trips_with_the_class_alias() -> None:
    policy = load_policy(DEFAULT_POLICY)
    dumped = policy.model_dump(mode="json", by_alias=True)
    assert dumped["tools"]["http.http_post"]["class"] == "egress"
    assert Policy.model_validate(dumped) == policy


def test_load_policy_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "missing.yaml")
