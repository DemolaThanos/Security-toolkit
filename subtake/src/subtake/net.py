from __future__ import annotations

import ipaddress
import re

from subtake.errors import SubtakeError

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")
# is_global is true for multicast, site-local, and these special-use ranges.
# Translation prefixes are refused outright so an embedded private address cannot be dialed.
_NOT_UNICAST = (
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 anycast relay
    ipaddress.ip_network("2001:1::/32"),  # Port Control Protocol anycast
    ipaddress.ip_network("2001:3::/32"),  # AMT
    ipaddress.ip_network("2001:4:112::/48"),  # AS112
    ipaddress.ip_network("2001:20::/28"),  # ORCHIDv2
    ipaddress.ip_network("3fff::/20"),  # documentation
    ipaddress.ip_network("2002::/16"),  # 6to4
    ipaddress.ip_network("2001::/32"),  # Teredo
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64
)


def normalize_hostname(host: str) -> str:
    """ASCII hostname. Rejects addresses, wildcards, and empty labels."""
    raw = host.strip().rstrip(".").lower()
    if not raw or len(raw) > 253 or any(ord(char) < 33 for char in raw):
        raise SubtakeError(f"not a hostname: {host!r}")
    try:
        ascii_name = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SubtakeError(f"not a hostname: {host!r}") from exc
    if len(ascii_name) > 253:
        raise SubtakeError(f"not a hostname: {host!r}")
    labels = ascii_name.split(".")
    if any(_LABEL.fullmatch(label) is None for label in labels):
        raise SubtakeError(f"not a hostname: {host!r}")
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        return ascii_name
    raise SubtakeError(f"not a hostname: {host!r}")


def usable_address(text: str) -> str | None:
    try:
        parsed: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if _rejected(parsed):
        return None
    return str(parsed)


def _rejected(parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(parsed, ipaddress.IPv6Address) and parsed in _SITE_LOCAL:
        return True
    if _listed(parsed):
        return True
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_reserved or parsed.is_loopback:
        return True
    return parsed.is_link_local or parsed.is_private or not parsed.is_global


def _listed(parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(parsed.version == network.version and parsed in network for network in _NOT_UNICAST)


def public_addresses(addresses: tuple[str, ...]) -> tuple[str, ...] | None:
    """Public unicast addresses, or None when any entry is not one.

    One bad answer rejects the whole set so a mixed reply cannot be used as a pivot.
    """
    if not addresses:
        return ()
    cleaned: list[str] = []
    for item in addresses:
        usable = usable_address(item)
        if usable is None:
            return None
        if usable not in cleaned:
            cleaned.append(usable)
    return tuple(cleaned)
