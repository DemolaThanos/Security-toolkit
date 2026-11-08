from __future__ import annotations

import http.client
import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

from corsprobe import __version__
from corsprobe.errors import InputError, ProbeFailure
from corsprobe.models import Target
from corsprobe.net import (
    Scope,
    connect_port,
    direct_address,
    guard_addresses,
    host_key,
    parse_target,
    request_url,
    same_host,
)

USER_AGENT = f"corsprobe/{__version__}"
_MAX_REDIRECTS = 3
_MAX_ADDRESSES = 4
_READ = 1024
_REDIRECTS = {301, 302, 303, 307, 308}
_BLOCKED_HEADERS = {
    "user-agent",
    "origin",
    "connection",
    "accept",
    "accept-encoding",
    "cache-control",
    "content-length",
    "transfer-encoding",
    "host",
    "cookie",
    "authorization",
}

Lookup = Callable[[str], tuple[str, ...]]


@dataclass(frozen=True)
class Call:
    method: str
    scheme: str
    host: str
    port: int
    path: str
    headers: tuple[tuple[str, str], ...]
    timeout: float
    addresses: tuple[str, ...]


Transport = Callable[[Call], tuple[int, tuple[tuple[str, str], ...]]]


class AddressPins:
    """First accepted answer for each host. Later lookups cannot move it onto a LAN."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._found: dict[str, tuple[tuple[str, ...], Scope]] = {}

    def resolve(self, host: str, lookup: Lookup) -> tuple[tuple[str, ...], Scope]:
        key = host_key(host)
        with self._lock:
            cached = self._found.get(key)
        if cached is not None:
            return cached
        resolved = guard_addresses(host, lookup(host))
        with self._lock:
            current = self._found.get(key)
            if current is None:
                self._found[key] = resolved
                return resolved
            if current[1] is not resolved[1]:
                raise ProbeFailure(f"{host} changed between public and private addresses")
            return current


def perform(
    url: str,
    *,
    method: str,
    origin: str,
    timeout: float,
    follow_off_host: bool,
    extra_headers: tuple[tuple[str, str], ...] = (),
    transport: Transport | None = None,
    lookup: Lookup | None = None,
    pins: AddressPins | None = None,
) -> tuple[int, tuple[tuple[str, str], ...], str]:
    if method not in {"GET", "OPTIONS"}:
        raise ProbeFailure("method is not allowed")
    headers = _headers(origin, extra_headers)
    send = transport or _transport
    resolve = lookup or system_lookup
    cache = pins if pins is not None else AddressPins()
    first_host: str | None = None
    first_scope: Scope | None = None
    current = url
    seen: set[str] = set()
    for hop in range(_MAX_REDIRECTS + 1):
        target = _destination(current)
        if target.raw in seen:
            raise ProbeFailure("redirect loop")
        seen.add(target.raw)
        addresses, scope = cache.resolve(target.host, resolve)
        if first_host is None:
            first_host = target.host
            first_scope = scope
        elif first_scope is Scope.PUBLIC and scope is Scope.PRIVATE and not same_host(first_host, target.host):
            raise ProbeFailure("refusing redirect from a public host to a private address")
        status, response_headers = _send(send, target, method, headers, timeout, addresses)
        location = _header(response_headers, "location") if status in _REDIRECTS else None
        final_url = request_url(target)
        if not location:
            return status, response_headers, final_url
        try:
            dest = parse_target(urljoin(final_url, location))
        except InputError as exc:
            raise ProbeFailure(str(exc)) from exc
        if target.scheme == "https" and dest.scheme != "https":
            return status, response_headers, final_url
        if not same_host(target.host, dest.host) and not follow_off_host:
            return status, response_headers, final_url
        if hop == _MAX_REDIRECTS:
            raise ProbeFailure(f"stopped after {_MAX_REDIRECTS} redirects")
        current = request_url(dest)
    raise ProbeFailure(f"stopped after {_MAX_REDIRECTS} redirects")


def system_lookup(host: str) -> tuple[str, ...]:
    direct = direct_address(host)
    if direct is not None:
        return (direct,)
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ProbeFailure(f"could not resolve {host}") from exc
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        address = sockaddr[0] if sockaddr else ""
        if isinstance(address, str) and address not in found:
            found.append(address)
    return tuple(found)


def _destination(url: str) -> Target:
    try:
        return parse_target(url)
    except InputError as exc:
        raise ProbeFailure(str(exc)) from exc


def _send(
    send: Transport,
    target: Target,
    method: str,
    headers: dict[str, str],
    timeout: float,
    addresses: tuple[str, ...],
) -> tuple[int, tuple[tuple[str, str], ...]]:
    call = Call(
        method,
        target.scheme,
        target.host,
        connect_port(target.scheme, target.port),
        target.path,
        tuple(headers.items()),
        timeout,
        addresses[:_MAX_ADDRESSES],
    )
    try:
        return send(call)
    except ProbeFailure:
        raise
    except TimeoutError as exc:
        raise ProbeFailure("timed out") from exc
    except ssl.SSLError as exc:
        raise ProbeFailure("tls failed") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise ProbeFailure("connection failed") from exc


def _transport(call: Call) -> tuple[int, tuple[tuple[str, str], ...]]:
    last: Exception | None = None
    for ip in call.addresses:
        try:
            conn = _open(call, ip)
        except ssl.SSLError as exc:
            last = exc
            continue
        except OSError as exc:
            last = exc
            continue
        try:
            # No body. GET and OPTIONS only; the caller already checked the method.
            conn.request(call.method, call.path, headers=dict(call.headers))
            response = conn.getresponse()
            response.read(_READ)
            status = int(response.status)
            pairs = tuple((str(key), str(value)) for key, value in response.getheaders())
            return status, pairs
        except (TimeoutError, ssl.SSLError):
            raise
        except (OSError, http.client.HTTPException) as exc:
            last = exc
        finally:
            conn.close()
    if isinstance(last, (TimeoutError, ssl.SSLError)):
        raise last
    raise ProbeFailure("connection failed") from last


def _open(call: Call, ip: str) -> http.client.HTTPConnection:
    raw = socket.create_connection((ip, call.port), call.timeout)
    if call.scheme == "http":
        plain = http.client.HTTPConnection(call.host, call.port, timeout=call.timeout)
        plain.sock = raw
        return plain
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        wrapped = context.wrap_socket(raw, server_hostname=call.host)
    except (TimeoutError, OSError, ssl.SSLError):
        raw.close()
        raise
    secure = http.client.HTTPSConnection(call.host, call.port, timeout=call.timeout, context=context)
    secure.sock = wrapped
    return secure


def _headers(origin: str, extra: tuple[tuple[str, str], ...]) -> dict[str, str]:
    if origin != "null" and not origin.startswith(("https://", "http://")):
        raise ProbeFailure("origin is not usable")
    if any(char in origin for char in "\r\n\x00 "):
        raise ProbeFailure("origin is not usable")
    built = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        "Connection": "close",
        "Origin": origin,
    }
    for name, value in extra:
        if name.lower() in _BLOCKED_HEADERS or not _token(name) or any(char in value for char in "\r\n\x00"):
            raise ProbeFailure("header is not allowed")
        built[name] = value
    return built


def _token(name: str) -> bool:
    return bool(name) and all(char.isalnum() or char in "-_" for char in name)


def _header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    key = name.lower()
    for header, value in headers:
        if header.lower() == key:
            return value.strip()
    return None
