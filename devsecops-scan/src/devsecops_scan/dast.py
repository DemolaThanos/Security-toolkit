from __future__ import annotations

import http.client
import logging
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from devsecops_scan.errors import TargetError
from devsecops_scan.models import Finding, Severity
from devsecops_scan.net import classify_host, ensure_redirect

logger = logging.getLogger("devsecops_scan.dast")

USER_AGENT = "devsecops-scan/0.1.0"
_MAX_REDIRECTS = 5


@dataclass(frozen=True)
class HttpResult:
    url: str
    final_url: str
    status: int
    headers: tuple[tuple[str, str], ...]


Connector = Callable[[str, str, int, float, bool], Any]


def scan_dast(
    url: str,
    *,
    authorized: bool,
    timeout: float,
    connector: Connector | None = None,
) -> list[Finding]:
    if not authorized:
        raise TargetError("passive DAST needs --i-am-authorized. Request only a host you are allowed to test.")
    result = fetch_headers(url, timeout=timeout, connector=connector)
    content_type = _first(result.headers, "content-type")
    scheme = urlsplit(result.final_url).scheme
    return evaluate_headers(
        result.headers,
        final_url=result.final_url,
        scheme=scheme,
        content_type=content_type,
    )


def fetch_headers(
    url: str,
    *,
    timeout: float,
    connector: Connector | None = None,
) -> HttpResult:
    _reject_credentials(url)
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise TargetError("DAST URL must be http or https and include a host")
    origin = classify_host(parts.hostname)
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        target = urlsplit(current)
        if target.scheme not in {"http", "https"} or target.hostname is None:
            raise TargetError(f"redirect target {current} is not an http(s) URL")
        if hop == 0:
            classify_host(target.hostname)
        else:
            ensure_redirect(origin, target.hostname)
        status, headers = _request(target.scheme, target.hostname, target.port, _path(target), timeout, connector)
        if status in {301, 302, 303, 307, 308}:
            location = _first(tuple(headers), "location")
            if not location:
                raise TargetError(f"redirect from {current} had no Location header")
            current = urljoin(current, location)
            _reject_credentials(current)
            continue
        return HttpResult(url=url, final_url=current, status=status, headers=tuple(headers))
    raise TargetError(f"stopped after {_MAX_REDIRECTS} redirects")


def evaluate_headers(
    headers: tuple[tuple[str, str], ...],
    *,
    final_url: str,
    scheme: str,
    content_type: str | None,
) -> list[Finding]:
    grouped = _group(headers)
    findings: list[Finding] = []

    def add(rule_id: str, severity: Severity, message: str) -> None:
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                tool="dast",
                path=final_url,
            )
        )

    if scheme != "https":
        add("not-https", Severity.HIGH, "final response is not HTTPS")
        return findings

    hsts = _one(grouped, "strict-transport-security")
    if hsts is None:
        add("hsts-missing", Severity.HIGH, "Strict-Transport-Security is absent")
    else:
        max_age = _max_age(hsts)
        if max_age is None or max_age < 15_552_000:
            shown = "missing" if max_age is None else str(max_age)
            add("hsts-max-age", Severity.MEDIUM, f"HSTS max-age is {shown}; use at least 15552000")

    csp = _one(grouped, "content-security-policy")
    html = bool(content_type and content_type.split(";", 1)[0].strip().lower() == "text/html")
    if csp is None:
        add(
            "csp-missing",
            Severity.HIGH if html else Severity.MEDIUM,
            "Content-Security-Policy is absent",
        )
    xcto = _one(grouped, "x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        add("x-content-type-options", Severity.MEDIUM, "X-Content-Type-Options is not nosniff")
    if not _clickjacking_ok(grouped, csp):
        add(
            "clickjacking",
            Severity.MEDIUM,
            "no X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors",
        )
    referrer = _one(grouped, "referrer-policy")
    if referrer is None:
        add("referrer-policy", Severity.MEDIUM, "Referrer-Policy is absent")
    elif referrer.strip().lower() == "unsafe-url":
        add("referrer-policy", Severity.HIGH, "Referrer-Policy is unsafe-url")
    return findings


def _request(
    scheme: str,
    host: str,
    port: int | None,
    path: str,
    timeout: float,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    resolved_port = port or (443 if scheme == "https" else 80)
    try:
        if scheme == "https":
            try:
                return _once(scheme, host, resolved_port, path, timeout, True, connector)
            except ssl.SSLError as exc:
                logger.info("TLS verification failed for %s: %s", host, exc.__class__.__name__)
                return _once(scheme, host, resolved_port, path, timeout, False, connector)
        return _once(scheme, host, resolved_port, path, timeout, True, connector)
    except TargetError:
        raise
    except (TimeoutError, OSError) as exc:
        raise TargetError(f"connection to {host}:{resolved_port} failed") from exc


def _once(
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: float,
    verify: bool,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    conn: Any = (connector or _default_connector)(scheme, host, port, timeout, verify)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        response.read(1024)
        return int(response.status), list(response.getheaders())
    finally:
        conn.close()


def _default_connector(scheme: str, host: str, port: int, timeout: float, verify: bool) -> Any:
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


def _path(parts: object) -> str:
    path = getattr(parts, "path", "") or "/"
    query = getattr(parts, "query", "")
    if query:
        return f"{path}?{query}"
    return path


def _reject_credentials(url: str) -> None:
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise TargetError("URL must not contain credentials")


def _group(headers: tuple[tuple[str, str], ...]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for name, value in headers:
        grouped.setdefault(name.lower(), []).append(value)
    return grouped


def _one(grouped: dict[str, list[str]], name: str) -> str | None:
    values = grouped.get(name)
    if not values:
        return None
    return values[0]


def _first(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _max_age(value: str) -> int | None:
    for part in value.split(";"):
        item = part.strip()
        if item.lower().startswith("max-age"):
            _, _, raw = item.partition("=")
            try:
                return int(raw.strip().strip('"'))
            except ValueError:
                return None
    return None


def _clickjacking_ok(grouped: dict[str, list[str]], csp: str | None) -> bool:
    xfo = _one(grouped, "x-frame-options")
    if xfo is not None and xfo.strip().lower() in {"deny", "sameorigin"}:
        return True
    if csp is None:
        return False
    for part in csp.split(";"):
        item = part.strip()
        if item.lower().startswith("frame-ancestors"):
            body = item.split(None, 1)[1] if " " in item else ""
            return "*" not in body.split()
    return False
