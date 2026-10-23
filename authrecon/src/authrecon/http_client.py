from __future__ import annotations

import http.client
import logging
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit

from authrecon.errors import TargetError
from authrecon.net import classify_host, ensure_redirect

logger = logging.getLogger("authrecon.http")

USER_AGENT = "authrecon/0.1.0"
_MAX_REDIRECTS = 5


class HttpResult:
    def __init__(self, url: str, final_url: str, status: int, headers: tuple[tuple[str, str], ...]) -> None:
        self.url = url
        self.final_url = final_url
        self.status = status
        self.headers = headers


Connector = Callable[[str, str, int, float, bool], Any]


def fetch_headers(
    url: str,
    *,
    timeout: float,
    connector: Connector | None = None,
) -> HttpResult:
    _reject_credentials(url)
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise TargetError("URL must be http or https and include a host")
    origin = classify_host(parts.hostname)
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        target = urlsplit(current)
        if target.scheme not in {"http", "https"} or target.hostname is None:
            raise TargetError("redirect target is not an http(s) URL")
        if hop == 0:
            classify_host(target.hostname)
        else:
            ensure_redirect(origin, target.hostname)
        try:
            status, headers = _request(
                target.scheme,
                target.hostname,
                target.port,
                _path(target),
                timeout,
                connector,
            )
        except TargetError:
            raise
        if status in {301, 302, 303, 307, 308}:
            location = _header(headers, "location")
            if not location:
                raise TargetError("redirect had no Location header")
            current = urljoin(current, location)
            _reject_credentials(current)
            continue
        return HttpResult(url, current, status, tuple(headers))
    raise TargetError(f"stopped after {_MAX_REDIRECTS} redirects")


def _request(
    scheme: str,
    host: str,
    port: int | None,
    path: str,
    timeout: float,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    resolved = port or (443 if scheme == "https" else 80)
    try:
        if scheme == "https":
            try:
                return _once(scheme, host, resolved, path, timeout, True, connector)
            except ssl.SSLError as exc:
                logger.info("TLS verification failed for %s: %s", host, exc.__class__.__name__)
                return _once(scheme, host, resolved, path, timeout, False, connector)
        return _once(scheme, host, resolved, path, timeout, True, connector)
    except TargetError:
        raise
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        raise TargetError(f"connection to {host}:{resolved} failed") from exc


def _once(
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: float,
    verify: bool,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    conn: Any = (connector or default_connector)(scheme, host, port, timeout, verify)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        response.read(1024)
        headers = response.getheaders()
        status = int(response.status)
    finally:
        conn.close()
    return status, list(headers)


def default_connector(scheme: str, host: str, port: int, timeout: float, verify: bool) -> Any:
    if scheme == "https":
        context = ssl.create_default_context() if verify else _unverified_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _path(parts: SplitResult) -> str:
    path = parts.path or "/"
    if parts.query:
        return f"{path}?{parts.query}"
    return path


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _reject_credentials(url: str) -> None:
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise TargetError("URL must not contain credentials")
