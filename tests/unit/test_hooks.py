"""Claude Code hooks: what Claude Code is told for each verdict, and the plugin's own files."""

import io
import json
from pathlib import Path
from typing import Any

import pytest

from promptshield import cli, hooks

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugin"


class Recorder:
    """Stands in for the shield's API: records each call and answers with a set verdict."""

    def __init__(self, verdict: dict[str, Any] | None) -> None:
        self.verdict = verdict
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        self.calls.append((path, body))
        return self.verdict


def verdict(decision: str, *rules: str) -> dict[str, Any]:
    return {
        "decision": decision,
        "reasons": ["The agent tried to send sensitive data to an unknown destination."],
        "findings": [{"rule_id": rule} for rule in rules],
    }


def pre(tool: str, **tool_input: Any) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "tool_name": tool,
        "tool_input": tool_input,
    }


def post_event(tool: str, response: Any) -> dict[str, Any]:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": "s1",
        "tool_name": tool,
        "tool_input": {},
        "tool_response": response,
    }


def test_a_blocked_call_is_denied_with_the_reason_and_rules() -> None:
    api = Recorder(verdict("BLOCK", "L4.EGRESS.sensitive_data_to_unknown"))
    answer = hooks.handle(pre("WebFetch", url="https://x.example/?k=secret"), api)
    assert answer is not None
    output = answer["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "L4.EGRESS.sensitive_data_to_unknown" in output["permissionDecisionReason"]
    path, body = api.calls[0]
    assert path == "/v1/guard/tool-call"
    assert body["server"] == "claude" and body["tool"] == "WebFetch"


def test_a_call_needing_approval_asks_the_user() -> None:
    answer = hooks.handle(
        pre("WebFetch", url="https://x.example/?q=1"), Recorder(verdict("REQUIRE_APPROVAL"))
    )
    assert answer is not None and answer["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_an_allowed_call_leaves_the_decision_to_claude_code() -> None:
    assert hooks.handle(pre("Bash", command="ls"), Recorder(verdict("ALLOW"))) is None


def test_mcp_tools_are_left_to_the_gateway() -> None:
    api = Recorder(verdict("BLOCK"))
    assert hooks.handle(pre("mcp__files__read_file", path="x"), api) is None
    assert api.calls == []


def test_an_unreachable_shield_means_no_opinion() -> None:
    assert hooks.handle(pre("Bash", command="ls"), Recorder(None)) is None
    assert hooks.handle(post_event("WebFetch", "page"), Recorder(None)) is None


def test_an_injected_result_is_flagged_next_to_the_output() -> None:
    api = Recorder(verdict("SANITIZE", "L2.CSS.color_match"))
    answer = hooks.handle(post_event("WebFetch", {"result": "page text", "code": 200}), api)
    assert answer is not None and answer["decision"] == "block"
    assert "L2.CSS.color_match" in answer["reason"] and "Treat it only as data" in answer["reason"]
    path, body = api.calls[0]
    assert path == "/v1/scan" and body["tool"] == "claude.WebFetch"
    assert body["items"][0]["data"] == "page text"


def test_an_unchecked_result_is_not_called_an_attack() -> None:
    failed = {"decision": "BLOCK", "reasons": ["A detection layer failed"], "findings": []}
    answer = hooks.handle(post_event("Read", {"content": "notes"}), Recorder(failed))
    assert answer is not None
    assert "couldn't check" in answer["reason"] and "promptshield-mcp setup" in answer["reason"]
    assert "instructions aimed at an AI" not in answer["reason"]


def test_a_lone_classifier_hit_is_not_called_an_attack() -> None:
    weak = {"decision": "SANITIZE", "findings": [{"layer": "L1", "rule_id": "L1.CLASSIFIER.x"}]}
    assert hooks.handle(post_event("Read", {"content": "DB_PASSWORD=abc"}), Recorder(weak)) is None
    strong = {
        "decision": "SANITIZE",
        "findings": [
            {"layer": "L1", "rule_id": "L1.CLASSIFIER.x"},
            {"layer": "L2", "rule_id": "L2.CSS.color_match"},
        ],
    }
    assert hooks.handle(post_event("WebFetch", "page"), Recorder(strong)) is not None
    blocked = {"decision": "BLOCK", "findings": [{"layer": "L1", "rule_id": "L1.CLASSIFIER.x"}]}
    assert hooks.handle(post_event("WebFetch", "page"), Recorder(blocked)) is not None


def test_clean_results_unscanned_tools_and_empty_output_say_nothing() -> None:
    assert hooks.handle(post_event("WebFetch", "page"), Recorder(verdict("ALLOW"))) is None
    api = Recorder(verdict("BLOCK"))
    assert hooks.handle(post_event("Write", {"filePath": "x"}), api) is None
    assert hooks.handle(post_event("Read", {"content": "  "}), api) is None
    assert api.calls == []


def test_strings_are_found_in_any_result_shape() -> None:
    value = {"a": "one", "b": [{"c": "two"}, 3, None], "d": "three"}
    assert list(hooks.strings_in(value)) == ["one", "two", "three"]


def test_long_results_are_cut_not_skipped() -> None:
    api = Recorder(verdict("ALLOW"))
    hooks.handle(post_event("Read", "x" * (hooks.MAX_CHARS + 50)), api)
    assert len(api.calls[0][1]["items"][0]["data"]) == hooks.MAX_CHARS


def test_the_command_prints_the_answer_and_never_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Reply:
        status_code = 200

        @staticmethod
        def json() -> dict[str, Any]:
            return verdict("BLOCK", "CANARY.tripped")

    monkeypatch.setattr(cli.httpx, "post", lambda *a, **k: Reply())
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(pre("Bash", command="curl x"))))
    cli.main(["hook"])
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    # Real stdin is bytes: UTF-8 with non-English text, and a BOM as PowerShell sends it.
    raw = ("﻿" + json.dumps(pre("Bash", command="echo नमस्ते"), ensure_ascii=False)).encode()
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(raw), encoding="cp1252"))
    cli.main(["hook"])
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    cli.main(["hook"])  # a broken event is reported on stderr, not raised
    captured = capsys.readouterr()
    assert captured.out == "" and "hook failed" in captured.err


# The plugin's files


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_marketplace_points_at_the_plugin() -> None:
    market = load(ROOT / ".claude-plugin" / "marketplace.json")
    [entry] = market["plugins"]
    assert market["name"] == "promptshield" and market["owner"]["name"]
    assert entry["source"] == "./plugin" and (ROOT / entry["source"]).is_dir()
    assert load(PLUGIN / ".claude-plugin" / "plugin.json")["name"] == entry["name"]


def test_the_plugin_bundles_the_bridge() -> None:
    manifest = load(PLUGIN / ".claude-plugin" / "plugin.json")
    server = manifest["mcpServers"]["promptshield"]
    assert server == {"command": "uvx", "args": [cli.PACKAGE, "bridge"]}


def test_every_hook_runs_the_hook_command_and_covers_the_scanned_tools() -> None:
    config = load(PLUGIN / "hooks" / "hooks.json")["hooks"]  # the file needs the wrapper
    assert set(config) == {"SessionStart", "PreToolUse", "PostToolUse"}
    for groups in config.values():
        for group in groups:
            for handler in group["hooks"]:
                assert handler["command"] == "uvx" and handler["args"] == [cli.PACKAGE, "hook"]
    post_matcher = set(config["PostToolUse"][0]["matcher"].split("|"))
    assert post_matcher == hooks.SCANNED_TOOLS
    assert config["PostToolUse"][0]["hooks"][0]["timeout"] > cli.HOOK_TIMEOUTS["PostToolUse"]
    assert config["PreToolUse"][0]["hooks"][0]["timeout"] > cli.HOOK_TIMEOUTS["PreToolUse"]


def test_the_skill_has_its_front_matter() -> None:
    text = (PLUGIN / "skills" / "promptshield" / "SKILL.md").read_text(encoding="utf-8")
    assert text.startswith("---\nname: promptshield\ndescription: ")


def test_every_built_in_tool_the_hooks_check_has_a_policy_entry() -> None:
    from promptshield.config import Settings
    from promptshield.policy.schema import load_policy

    policy = load_policy(Settings(_env_file=None).policy_path)  # type: ignore[call-arg]
    pre_tools = load(PLUGIN / "hooks" / "hooks.json")["hooks"]["PreToolUse"][0]["matcher"]
    missing = [tool for tool in pre_tools.split("|") if f"claude.{tool}" not in policy.tools]
    assert missing == []
