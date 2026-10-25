from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum

from authrecon.errors import ConnectError, PolicyError

# inet_aton accepts hex, octal, and short forms. 0xa9fea9fe is the metadata address.
_AMBIGUOUS = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$", re.IGNORECASE)
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")


class HostClass(Enum):
    PUBLIC = "public"
    PRIVATE = "private"


@dataclass(frozen=True)
class ResolvedHost:
    name: str
    host_class: HostClass
    addresses: tuple[str, ...]


def classify_host(host: str) -> HostClass:
    return resolve_host(host).host_class


def resolve_host(host: str) -> ResolvedHost:
    """Look up a host once. Callers connect to `addresses`, not to a later lookup."""
    name = _normalize_host(host)
    literal = _parse_literal(name)
    if literal is not None:
        ip = _unwrap(literal)
        _reject(ip)
        text = str(ip)
        return ResolvedHost(text, _class_from_ips([ip]), (text,))
    if _AMBIGUOUS.fullmatch(name):
        raise PolicyError(f"refusing non-canonical address {name}")
    encoded = _idna(name)
    ips = _lookup(encoded)
    ordered: list[str] = []
    seen: set[str] = set()
    for ip in ips:
        text = str(ip)
        if text not in seen:
            seen.add(text)
            ordered.append(text)
    return ResolvedHost(encoded, _class_from_ips(ips), tuple(ordered))


def ensure_redirect(origin: HostClass, dest: ResolvedHost) -> None:
    if origin is HostClass.PUBLIC and dest.host_class is HostClass.PRIVATE:
        raise PolicyError(f"refusing redirect from a public host to {dest.name}")


def host_key(host: str) -> str:
    """Stable identity so a later request to the same host reuses the first answer."""
    name = host.strip().rstrip(".").lower()
    literal = _parse_literal(name)
    if literal is not None:
        return str(_unwrap(literal))
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def connect_pinned(addresses: tuple[str, ...], port: int, timeout: float) -> socket.socket:
    last: OSError | None = None
    for ip in addresses:
        try:
            return socket.create_connection((ip, port), timeout)
        except OSError as exc:
            last = exc
    raise ConnectError("connection failed") from last


def _lookup(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PolicyError(f"could not resolve {host}") from exc
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        parsed = _parse_literal(str(info[4][0]))
        if parsed is None:
            raise PolicyError(f"resolver returned an invalid address for {host}")
        ips.append(_unwrap(parsed))
    if not ips:
        raise PolicyError(f"could not resolve {host}")
    for ip in ips:
        _reject(ip)
    return ips


def _normalize_host(host: str) -> str:
    name = host.strip().rstrip(".")
    if not name or len(name) > 253 or any(ord(char) < 33 or char in "/\\@#%?" for char in name):
        raise PolicyError("URL host is not usable")
    return name


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyError("URL host is not usable") from exc


def _parse_literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _unwrap(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    mapped = getattr(ip, "ipv4_mapped", None)
    if isinstance(mapped, ipaddress.IPv4Address):
        return mapped
    return ip


def _class_from_ips(ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> HostClass:
    if any(ip.is_loopback or ip.is_private for ip in ips) and any(ip.is_global for ip in ips):
        raise PolicyError("host resolves to both public and private addresses")
    if all(ip.is_loopback or ip.is_private for ip in ips):
        return HostClass.PRIVATE
    return HostClass.PUBLIC


def _reject(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    reason = _reject_reason(ip)
    if reason is not None:
        raise PolicyError(f"refusing {reason} address {ip}")


def _reject_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip in _SITE_LOCAL:
        return "site-local"
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
    if ip.is_private or ip.is_global:
        return None
    return "non-routable"
