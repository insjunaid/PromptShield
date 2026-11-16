"""Decides whether a URL or email recipient is allowed.

Hosts are converted to one standard form first. `127.1`, `0x7f.1`, `2130706433` and `foo.localhost`
all reach this machine, so comparing raw strings would let an attacker walk around the deny list.
"""

import socket
from dataclasses import dataclass
from email.utils import getaddresses
from fnmatch import fnmatchcase
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal
from urllib.parse import urlsplit

LOCALHOST = "localhost"
DEFAULT_PORTS = {"http": 80, "https": 443}

DestinationStatus = Literal["allowed", "denied", "unknown"]


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int | None


def _parse_ip(host: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(host)
    except ValueError:
        pass
    try:
        # inet_aton accepts the short, hex and decimal forms that ip_address refuses.
        return IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def canonical_host(host: str) -> str:
    """Return one standard spelling, mapping every local address to `localhost`."""
    cleaned = host.strip().lower().rstrip(".").strip("[]")
    if cleaned == LOCALHOST or cleaned.endswith(f".{LOCALHOST}"):
        return LOCALHOST
    address = _parse_ip(cleaned)
    if address is None:
        return cleaned
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_unspecified:
        return LOCALHOST
    return str(address)


def parse_url(url: str) -> Endpoint | None:
    """Return where a URL really goes, or None if that can't be determined."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not parts.hostname:
        return None
    return Endpoint(canonical_host(parts.hostname), port or DEFAULT_PORTS[scheme])


def parse_host_entry(entry: str) -> Endpoint:
    """Parse a policy entry such as `localhost:8081` or `company.example`."""
    if "://" in entry or "/" in entry:
        raise ValueError(f"host entry must be host or host:port, got {entry!r}")
    parts = urlsplit(f"//{entry}")
    if not parts.hostname:
        raise ValueError(f"host entry has no host: {entry!r}")
    host = canonical_host(parts.hostname)
    if host == LOCALHOST and parts.port is None:
        raise ValueError(f"a local host entry needs a port, got {entry!r}")
    return Endpoint(host, parts.port)


def _matches(endpoint: Endpoint, entry: str) -> bool:
    rule = parse_host_entry(entry)
    if rule.port is not None and rule.port != endpoint.port:
        return False
    return endpoint.host == rule.host or endpoint.host.endswith(f".{rule.host}")


def _recipients_allowed(value: str, patterns: list[str]) -> bool:
    """Every recipient must match, or one allowed address could carry an attacker's along."""
    addresses = [address.lower() for _, address in getaddresses([value]) if address]
    if not addresses:
        return False
    return all(
        any(fnmatchcase(address, pattern.lower()) for pattern in patterns) for address in addresses
    )


def classify_destination(
    value: object, allow_hosts: list[str], deny_hosts: list[str], allow_recipients: list[str]
) -> DestinationStatus:
    """Classify a tool's destination argument. Anything unclear is `unknown`, never `allowed`."""
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    if "://" not in value:
        allowed = "@" in value and _recipients_allowed(value, allow_recipients)
        return "allowed" if allowed else "unknown"
    endpoint = parse_url(value)
    if endpoint is None:
        return "unknown"
    if any(_matches(endpoint, entry) for entry in deny_hosts):
        return "denied"
    if any(_matches(endpoint, entry) for entry in allow_hosts):
        return "allowed"
    return "unknown"
