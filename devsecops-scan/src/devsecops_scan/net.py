from __future__ import annotations

import ipaddress
import socket
from enum import Enum

from devsecops_scan.errors import TargetError


class HostClass(Enum):
    PUBLIC = "public"
    PRIVATE = "private"


def classify_host(host: str) -> HostClass:
    """Reject link-local and other non-routable targets before any connection.

    Python treats 169.254.0.0/16 as private as well as link-local. Link-local is
    checked first so cloud metadata addresses are never scanned.
    """
    literal = _parse_literal(host)
    if literal is not None:
        return _class_from_ips([literal])
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetError(f"could not resolve {host}") from exc
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        parsed = _parse_literal(str(info[4][0]))
        if parsed is None:
            raise TargetError(f"resolver returned an invalid address for {host}")
        ips.append(parsed)
    if not ips:
        raise TargetError(f"could not resolve {host}")
    return _class_from_ips(ips)


def ensure_redirect(origin: HostClass, host: str) -> HostClass:
    dest = classify_host(host)
    if origin is HostClass.PUBLIC and dest is HostClass.PRIVATE:
        raise TargetError(f"refusing redirect from a public host to {host}")
    return dest


def _parse_literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _class_from_ips(
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> HostClass:
    for ip in ips:
        reason = _reject_reason(ip)
        if reason is not None:
            raise TargetError(f"refusing {reason} address {ip}")
    if any(ip.is_loopback or ip.is_private for ip in ips) and any(ip.is_global for ip in ips):
        raise TargetError("host resolves to both public and private addresses")
    if all(ip.is_loopback or ip.is_private for ip in ips):
        return HostClass.PRIVATE
    return HostClass.PUBLIC


def _reject_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
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
