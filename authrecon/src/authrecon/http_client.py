from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit

from authrecon.errors import ConnectError, PolicyError
from authrecon.net import ResolvedHost, ensure_redirect, resolve_host

logger = logging.getLogger("authrecon.http")

USER_AGENT = "authrecon/0.1.0"
_MAX_REDIRECTS = 5
_MAX_URL = 2048

Connector = Callable[[str, str, int, float, bool], Any]


class HttpResult:
    def __init__(self, url: str, final_url: str, status: int, headers: tuple[tuple[str, str], ...]) -> None:
        self.url = url
        self.final_url = final_url
        self.status = status
        self.headers = headers


def fetch_headers(
    url: str,
    *,
    timeout: float,
    connector: Connector | None = None,
) -> HttpResult:
    _reject_credentials(url)
    if len(url) > _MAX_URL:
        raise PolicyError("URL is too long")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise PolicyError("URL must be http or https and include a host")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise PolicyError("URL port is out of range")
    origin_name = parts.hostname
    origin = resolve_host(origin_name)
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        target = urlsplit(current)
        if target.scheme not in {"http", "https"} or target.hostname is None:
            raise PolicyError("redirect target is not an http(s) URL")
        if target.port is not None and not 1 <= target.port <= 65535:
            raise PolicyError("URL port is out of range")
        reuse = hop == 0 and _same_host(origin_name, target.hostname)
        resolved = origin if reuse else resolve_host(target.hostname)
        if hop:
            if not _same_host(origin_name, target.hostname):
                raise PolicyError("refusing redirect to a different host")
            ensure_redirect(origin.host_class, resolved)
        try:
            status, headers = _request(
                target.scheme,
                resolved,
                target.port,
                _path(target),
                timeout,
                connector,
            )
        except PolicyError:
            raise
        if status in {301, 302, 303, 307, 308}:
            location = _header(headers, "location")
            if not location:
                raise ConnectError("redirect had no Location header")
            current = urljoin(current, location)
            if len(current) > _MAX_URL:
                raise PolicyError("URL is too long")
            _reject_credentials(current)
            continue
        return HttpResult(url, current, status, tuple(headers))
    raise PolicyError(f"stopped after {_MAX_REDIRECTS} redirects")


def _request(
    scheme: str,
    resolved: ResolvedHost,
    port: int | None,
    path: str,
    timeout: float,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    resolved_port = port or (443 if scheme == "https" else 80)
    try:
        if scheme == "https":
            try:
                return _once(scheme, resolved, resolved_port, path, timeout, True, connector)
            except ssl.SSLCertVerificationError:
                logger.info("TLS verification failed for %s", resolved.name)
                return _once(scheme, resolved, resolved_port, path, timeout, False, connector)
        return _once(scheme, resolved, resolved_port, path, timeout, True, connector)
    except PolicyError:
        raise
    except (TimeoutError, OSError, ssl.SSLError, http.client.HTTPException, ConnectError) as exc:
        raise ConnectError(f"connection to {resolved.name}:{resolved_port} failed") from exc


def _once(
    scheme: str,
    resolved: ResolvedHost,
    port: int,
    path: str,
    timeout: float,
    verify: bool,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    conn: Any = (
        connector(scheme, resolved.name, port, timeout, verify)
        if connector
        else _open(scheme, resolved, port, timeout, verify)
    )
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        response.read(1024)
        headers = response.getheaders()
        status = int(response.status)
    finally:
        conn.close()
    return status, list(headers)


def _open(scheme: str, resolved: ResolvedHost, port: int, timeout: float, verify: bool) -> http.client.HTTPConnection:
    context = _tls_context(verify) if scheme == "https" else None
    ssl_error: ssl.SSLError | None = None
    os_error: OSError | None = None
    for ip in resolved.addresses:
        try:
            raw = socket.create_connection((ip, port), timeout)
        except OSError as exc:
            os_error = exc
            continue
        if context is None:
            conn: http.client.HTTPConnection = http.client.HTTPConnection(resolved.name, port, timeout=timeout)
            conn.sock = raw
            return conn
        try:
            wrapped = context.wrap_socket(raw, server_hostname=resolved.name)
        except ssl.SSLError as exc:
            raw.close()
            ssl_error = exc
            continue
        secure = http.client.HTTPSConnection(resolved.name, port, timeout=timeout, context=context)
        secure.sock = wrapped
        return secure
    if ssl_error is not None:
        raise ssl_error
    raise ConnectError(f"connection to {resolved.name}:{port} failed") from os_error


def _tls_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _path(parts: SplitResult) -> str:
    path = parts.path or "/"
    target = f"{path}?{parts.query}" if parts.query else path
    if any(char in target for char in "\r\n\x00"):
        raise PolicyError("URL path is not usable")
    return target


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _same_host(left: str, right: str) -> bool:
    return _identity(left) == _identity(right)


def _identity(host: str) -> str:
    name = host.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        try:
            return name.encode("idna").decode("ascii")
        except UnicodeError:
            return name


def _reject_credentials(url: str) -> None:
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise PolicyError("URL must not contain credentials")
