from __future__ import annotations

import ipaddress
import re
from enum import Enum
from urllib.parse import urlsplit

from corsprobe.errors import InputError, ProbeFailure
from corsprobe.models import Target

_MAX_URL = 2048
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# inet_aton accepts hex, octal, and short forms. 0xa9fea9fe is the metadata address.
_AMBIGUOUS = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$", re.IGNORECASE)
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")


def _ipv4(first: int, second: int, third: int, fourth: int, prefix: int) -> ipaddress.IPv4Network:
    packed = (first << 24) | (second << 16) | (third << 8) | fourth
    return ipaddress.IPv4Network((packed, prefix))


def _ipv6(hextets: tuple[int, ...], prefix: int) -> ipaddress.IPv6Network:
    value = 0
    for part in hextets:
        value = (value << 16) | part
    value <<= 16 * (8 - len(hextets))
    return ipaddress.IPv6Network((value, prefix))


# Loopback is separate. A named staging host may resolve into these only.
_LAN_V4 = (
    _ipv4(10, 0, 0, 0, 8),
    _ipv4(172, 16, 0, 0, 12),
    _ipv4(192, 168, 0, 0, 16),
)
_ULA = _ipv6((0xFC00,), 7)
# is_private is not a LAN. It includes documentation, benchmarking, and 6to4,
# and Python 3.11 and 3.12 disagree about 3fff::/20. is_global is true for the
# 6to4 relay and for the ranges below that the stdlib lists as exceptions.
# subtake refuses the same transition and special-use set. 2001:30::/28 is the
# deprecated ORCHID block, which the stdlib also treats as global.
_SPECIAL_V4: tuple[tuple[ipaddress.IPv4Network, str], ...] = ((_ipv4(192, 88, 99, 0, 24), "6to4-relay"),)
_SPECIAL_V6: tuple[tuple[ipaddress.IPv6Network, str], ...] = (
    (_ipv6((0x2002,), 16), "6to4"),
    (_ipv6((0x2001,), 32), "teredo"),
    (_ipv6((0x0064, 0xFF9B), 96), "nat64"),
    (_ipv6((0x0064, 0xFF9B, 1), 48), "nat64"),
    (_ipv6((0x3FFF,), 20), "documentation"),
    (_ipv6((0x2001, 1), 32), "special-use"),
    (_ipv6((0x2001, 3), 32), "special-use"),
    (_ipv6((0x2001, 4, 0x0112), 48), "special-use"),
    (_ipv6((0x2001, 0x0020), 28), "special-use"),
    (_ipv6((0x2001, 0x0030), 28), "special-use"),
)


class Scope(Enum):
    PUBLIC = "public"
    PRIVATE = "private"


def parse_target(raw: str) -> Target:
    text = raw.strip()
    parts = _split_url(text)
    return Target(text, parts[0], parts[1], parts[2], parts[3])


def parse_trusted(value: str) -> str:
    text = value.strip()
    if not text or any(ord(char) < 33 or ord(char) == 127 for char in text):
        raise InputError("trusted domain must be a hostname")
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme not in {"http", "https"} or parts.hostname is None:
            raise InputError("trusted domain must be a hostname")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise InputError("trusted domain must be a hostname")
        if parts.path not in {"", "/"}:
            raise InputError("trusted domain must be a hostname")
        host = parts.hostname
    else:
        if any(char in text for char in "/?#@"):
            raise InputError("trusted domain must be a hostname")
        host = text
    if host.startswith("*."):
        raise InputError("pass the trusted domain without a wildcard")
    name = normalize_hostname(host)
    if _literal(name) is not None:
        raise InputError("trusted domain must be a hostname")
    return name


def normalize_hostname(host: str) -> str:
    name = host.strip().rstrip(".").lower()
    if not name or len(name) > 253 or any(ord(char) < 33 for char in name):
        raise InputError(f"not a hostname: {host!r}")
    literal = _literal(name)
    if literal is not None:
        return str(_unwrap(literal))
    if _AMBIGUOUS.fullmatch(name):
        raise InputError(f"refusing non-canonical address {host}")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InputError(f"not a hostname: {host!r}") from exc
    if len(ascii_name) > 253:
        raise InputError(f"not a hostname: {host!r}")
    labels = ascii_name.split(".")
    if any(_LABEL.fullmatch(label) is None for label in labels):
        raise InputError(f"not a hostname: {host!r}")
    return ascii_name


def request_url(target: Target) -> str:
    return join_url(target.scheme, target.host, target.port, target.path)


def join_url(scheme: str, host: str, port: int | None, path: str) -> str:
    shown = f"[{host}]" if ":" in host else host
    authority = shown if port is None or _default_port(scheme, port) else f"{shown}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{authority}{path}"


def format_origin(scheme: str, host: str, port: int | None) -> str:
    shown = f"[{host}]" if ":" in host else host
    if port is None or _default_port(scheme, port):
        return f"{scheme}://{shown}"
    return f"{scheme}://{shown}:{port}"


def host_key(host: str) -> str:
    name = host.strip().rstrip(".").lower()
    literal = _literal(name)
    if literal is not None:
        return str(_unwrap(literal))
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def same_host(left: str, right: str) -> bool:
    return host_key(left) == host_key(right)


def is_dns_name(host: str) -> bool:
    return _literal(host) is None


def connect_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def direct_address(host: str) -> str | None:
    """An address literal, or None when `host` still needs DNS.

    Short and hex forms never reach the resolver. glibc would otherwise
    accept some of them as numbers.
    """
    name = host.strip()
    if _AMBIGUOUS.fullmatch(name) and _literal(name) is None:
        raise ProbeFailure(f"refusing non-canonical address {name}")
    parsed = _literal(name)
    if parsed is None:
        return None
    return str(_unwrap(parsed))


def guard_addresses(host: str, addresses: tuple[str, ...]) -> tuple[tuple[str, ...], Scope]:
    """Keep a public or private set. One rejected address refuses the lot."""
    if not addresses:
        raise ProbeFailure(f"could not resolve {host}")
    if len(addresses) > 32:
        raise ProbeFailure(f"too many addresses for {host}")
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for item in addresses:
        parsed.append(_accept(item))
    scopes = {_scope(ip) for ip in parsed}
    if len(scopes) != 1:
        raise ProbeFailure(f"{host} resolves to both public and private addresses")
    ordered: list[str] = []
    for ip in parsed:
        text = str(ip)
        if text not in ordered:
            ordered.append(text)
    return tuple(ordered), scopes.pop()


def _default_port(scheme: str, port: int) -> bool:
    return (scheme == "https" and port == 443) or (scheme == "http" and port == 80)


def _split_url(text: str) -> tuple[str, str, int | None, str]:
    if not text or len(text) > _MAX_URL:
        raise InputError("URL is empty or too long")
    if any(char.isspace() or ord(char) == 127 for char in text):
        raise InputError("URL contains unsupported characters")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise InputError(f"URL must be http or https and include a host: {text}")
    if parts.username or parts.password:
        raise InputError("URL must not contain credentials")
    try:
        port = parts.port
    except ValueError as exc:
        raise InputError("URL port is out of range") from exc
    if port is not None and not 1 <= port <= 65535:
        raise InputError("URL port is out of range")
    try:
        host = normalize_hostname(parts.hostname)
    except InputError as exc:
        raise InputError(f"{text}: {exc}") from exc
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    if any(ord(char) < 32 or ord(char) > 126 for char in path):
        raise InputError("URL path is not usable")
    return parts.scheme, host, port, path


def _literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _unwrap(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _accept(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if _AMBIGUOUS.fullmatch(text) and _literal(text) is None:
        raise ProbeFailure(f"refusing non-canonical address {text}")
    parsed = _literal(text)
    if parsed is None:
        raise ProbeFailure(f"resolver returned an invalid address {text}")
    ip = _unwrap(parsed)
    reason = _reject_reason(ip)
    if reason is not None:
        raise ProbeFailure(f"refusing {reason} address {ip}")
    return ip


def _reject_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    # 169.254.169.254 is link-local. is_private is also true; the link-local check wins.
    if isinstance(ip, ipaddress.IPv6Address) and ip in _SITE_LOCAL:
        return "site-local"
    special = _special_use(ip)
    if special is not None:
        return special
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    if ip.is_loopback:
        return None
    if ip.is_reserved:
        return "reserved"
    # Documentation and benchmarking addresses are is_private and are not a LAN.
    if _is_lan(ip) or ip.is_global:
        return None
    return "non-routable"


def _special_use(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if isinstance(ip, ipaddress.IPv4Address):
        for network, reason in _SPECIAL_V4:
            if ip in network:
                return reason
        return None
    for block, reason in _SPECIAL_V6:
        if ip in block:
            return reason
    return None


def _is_lan(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in network for network in _LAN_V4)
    return ip in _ULA


def _scope(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Scope:
    if ip.is_loopback or _is_lan(ip):
        return Scope.PRIVATE
    return Scope.PUBLIC
