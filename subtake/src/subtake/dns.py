from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

import dns.exception
import dns.resolver

from subtake.errors import SubtakeError
from subtake.net import normalize_hostname

_MAX_CHAIN = 8


@dataclass(frozen=True)
class QueryResult:
    names: tuple[str, ...] = ()
    nxdomain: bool = False
    error: str | None = None


class Lookup(Protocol):
    def query(self, name: str, rdtype: str) -> QueryResult: ...


@dataclass(frozen=True)
class Chain:
    host: str
    cnames: tuple[str, ...]
    missing: bool
    terminal_nxdomain: bool
    addresses: tuple[str, ...]
    error: str | None


class _Rdata(Protocol):
    def to_text(self) -> str: ...


class _Resolver(Protocol):
    lifetime: float
    timeout: float

    def resolve(self, qname: str, rdtype: str, *, search: bool = ...) -> Iterable[_Rdata]: ...


def resolve_chain(host: str, lookup: Lookup) -> Chain:
    current = host
    seen = {host}
    cnames: list[str] = []
    for _ in range(_MAX_CHAIN):
        answer = lookup.query(current, "CNAME")
        if answer.error:
            return Chain(host, tuple(cnames), False, False, (), answer.error)
        if answer.nxdomain:
            if not cnames:
                return Chain(host, (), True, False, (), None)
            return Chain(host, tuple(cnames), False, True, (), None)
        if not answer.names:
            if not cnames:
                return Chain(host, (), False, False, (), None)
            break
        try:
            target = normalize_hostname(answer.names[0])
        except SubtakeError:
            return Chain(host, tuple(cnames), False, False, (), "unusable CNAME target")
        if target in seen:
            return Chain(host, tuple(cnames), False, False, (), f"CNAME loop at {target}")
        seen.add(target)
        cnames.append(target)
        current = target
    else:
        return Chain(host, tuple(cnames), False, False, (), f"CNAME chain is longer than {_MAX_CHAIN}")

    addresses, error, nxdomain = _addresses(lookup, current)
    if nxdomain:
        return Chain(host, tuple(cnames), False, True, (), None)
    if error:
        return Chain(host, tuple(cnames), False, False, (), error)
    return Chain(host, tuple(cnames), False, False, addresses, None)


def _addresses(lookup: Lookup, name: str) -> tuple[tuple[str, ...], str | None, bool]:
    v4 = lookup.query(name, "A")
    if v4.nxdomain:
        return (), None, True
    if any(_not_ip(item) for item in v4.names):
        return (), "unusable address", False
    v6 = lookup.query(name, "AAAA")
    if v6.nxdomain and not v4.names and not v4.error:
        return (), None, True
    if any(_not_ip(item) for item in v6.names):
        return (), "unusable address", False
    if v4.error and (v6.error or not v6.names):
        return (), v4.error, False
    if v6.error and not v4.names:
        return (), v6.error, False
    addresses: list[str] = []
    for item in (*(() if v4.error else v4.names), *(() if v6.error else v6.names)):
        if item not in addresses:
            addresses.append(item)
    return tuple(addresses[:8]), None, False


def _not_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


class SystemLookup:
    def __init__(self, timeout: float, resolver_factory: Callable[[], _Resolver] | None = None) -> None:
        self._timeout = timeout
        self._factory = resolver_factory or _resolver

    def query(self, name: str, rdtype: str) -> QueryResult:
        try:
            ascii_name = normalize_hostname(name)
        except SubtakeError:
            return QueryResult(error="unusable name")
        resolver = self._factory()
        resolver.lifetime = self._timeout
        resolver.timeout = self._timeout
        try:
            # search=False keeps a resolver search list from appending another suffix.
            answer = resolver.resolve(ascii_name, rdtype, search=False)
        except dns.resolver.NXDOMAIN:
            return QueryResult(nxdomain=True)
        except dns.resolver.NoAnswer:
            return QueryResult()
        except dns.exception.Timeout:
            return QueryResult(error="dns timeout")
        except dns.exception.DNSException:
            return QueryResult(error="dns lookup failed")
        names = tuple(_rdata_text(item) for item in answer)
        return QueryResult(names=names)


def _resolver() -> _Resolver:
    return dns.resolver.Resolver()


def _rdata_text(item: _Rdata) -> str:
    return item.to_text().strip().rstrip(".").lower()
