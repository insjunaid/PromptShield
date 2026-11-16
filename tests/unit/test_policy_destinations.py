"""Destination checks are the last line against exfiltration, so test the bypass attempts."""

import pytest

from promptshield.policy.destinations import (
    Endpoint,
    canonical_host,
    classify_destination,
    parse_host_entry,
    parse_url,
)

ALLOW = ["localhost:8081", "company.example"]
DENY = ["localhost:8000", "localhost:8765"]
RECIPIENTS = ["*@company.example"]


def classify(value: object) -> str:
    return classify_destination(value, ALLOW, DENY, RECIPIENTS)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "foo.localhost",
        "127.0.0.1",
        "127.1",
        "127.0.0.2",
        "0x7f.1",
        "0177.0.0.1",
        "2130706433",
        "0.0.0.0",
        "::1",
        "[::1]",
        "::ffff:127.0.0.1",
    ],
)
def test_every_spelling_of_this_machine_is_localhost(host: str) -> None:
    assert canonical_host(host) == "localhost"


@pytest.mark.parametrize("host", ["company.example", "evil.example", "8.8.8.8"])
def test_other_hosts_are_not_localhost(host: str) -> None:
    assert canonical_host(host) != "localhost"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000/v1/policy/mode",
        "http://127.0.0.1:8000/v1/approvals/1",
        "http://127.1:8000/v1/policy",
        "http://2130706433:8000/",
        "http://0x7f.1:8000/",
        "http://[::1]:8000/",
        "http://foo.localhost:8000/",
        "http://0.0.0.0:8765/mcp",
        "HTTP://LOCALHOST:8000/",
        "http://user:pw@localhost:8000/",
    ],
)
def test_control_plane_is_denied_however_it_is_spelled(url: str) -> None:
    assert classify(url) == "denied"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:9999/collect",
        "http://127.0.0.1:9999/collect",
        "http://localhost/",
        "http://evil.example/",
    ],
)
def test_sink_and_outside_hosts_are_unknown_not_allowed(url: str) -> None:
    assert classify(url) == "unknown"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8081/page.html",
        "http://127.0.0.1:8081/page.html",
        "https://company.example/report",
        "https://files.company.example/report",
    ],
)
def test_allowlisted_urls_are_allowed(url: str) -> None:
    assert classify(url) == "allowed"


@pytest.mark.parametrize(
    "url",
    [
        "http://company.example.evil.example/",
        "http://evilcompany.example/",
        "http://company.example@evil.example/",
        "http://localhost:8081@evil.example/",
        "file:///etc/passwd",
        "ftp://company.example/",
        "http://",
        "http://localhost:notaport/",
    ],
)
def test_lookalike_urls_are_not_allowed(url: str) -> None:
    assert classify(url) == "unknown"


def test_port_on_an_allow_entry_is_enforced() -> None:
    assert classify_destination("http://x.example:8443/", ["x.example:443"], [], []) == "unknown"
    assert classify_destination("https://x.example/", ["x.example:443"], [], []) == "allowed"


def test_deny_beats_allow() -> None:
    assert (
        classify_destination("http://localhost:8000/", ["localhost:8000"], ["localhost:8000"], [])
        == "denied"
    )


@pytest.mark.parametrize(
    "value",
    [
        "boss@company.example",
        "BOSS@Company.Example",
        "Boss <boss@company.example>",
        "boss@company.example, team@company.example",
        ["boss@company.example", "team@company.example"],
    ],
)
def test_allowed_recipients(value: object) -> None:
    assert classify(value) == "allowed"


@pytest.mark.parametrize(
    "value",
    [
        "it-support@attacker.local",
        "boss@company.example, it-support@attacker.local",
        ["boss@company.example", "it-support@attacker.local"],
        "boss@company.example.attacker.local",
        "not-an-address",
    ],
)
def test_any_unknown_recipient_makes_it_unknown(value: object) -> None:
    assert classify(value) == "unknown"


@pytest.mark.parametrize("value", [None, "", "   ", 42, {"to": "x"}])
def test_unusable_destinations_are_unknown(value: object) -> None:
    assert classify(value) == "unknown"


def test_url_defaults_to_the_scheme_port() -> None:
    assert parse_url("https://example.org/x") == Endpoint("example.org", 443)
    assert parse_url("http://example.org/x") == Endpoint("example.org", 80)


@pytest.mark.parametrize("entry", ["localhost", "127.0.0.1", "http://x.example", "x.example/path"])
def test_bad_host_entries_are_refused(entry: str) -> None:
    with pytest.raises(ValueError):
        parse_host_entry(entry)
