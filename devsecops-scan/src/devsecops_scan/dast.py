from __future__ import annotations

import http.client
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit

from devsecops_scan.errors import TargetError
from devsecops_scan.models import Finding, Severity
from devsecops_scan.net import ResolvedHost, ensure_redirect, open_http, resolve_host

USER_AGENT = "devsecops-scan/0.1.0"
_MAX_REDIRECTS = 5
_MAX_URL = 2048

Connector = Callable[[str, str, int, float, bool], Any]


@dataclass(frozen=True)
class HttpResult:
    url: str
    final_url: str
    status: int
    headers: tuple[tuple[str, str], ...]


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
    if len(url) > _MAX_URL:
        raise TargetError("URL is too long")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise TargetError("DAST URL must be http or https and include a host")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise TargetError("URL port is out of range")
    origin = resolve_host(parts.hostname)
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        target = urlsplit(current)
        if target.scheme not in {"http", "https"} or target.hostname is None:
            raise TargetError("redirect target is not an http(s) URL")
        if target.port is not None and not 1 <= target.port <= 65535:
            raise TargetError("URL port is out of range")
        resolved = origin if hop == 0 and _same_host(parts.hostname, target.hostname) else resolve_host(target.hostname)
        if hop:
            ensure_redirect(origin.host_class, resolved)
        status, headers = _request(
            target.scheme,
            resolved,
            target.port,
            _path(target),
            timeout,
            connector,
        )
        if status in {301, 302, 303, 307, 308}:
            location = _first(tuple(headers), "location")
            if not location:
                raise TargetError("redirect had no Location header")
            current = urljoin(current, location)
            if len(current) > _MAX_URL:
                raise TargetError("URL is too long")
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
    resolved: ResolvedHost,
    port: int | None,
    path: str,
    timeout: float,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    resolved_port = port or (443 if scheme == "https" else 80)
    try:
        return _once(scheme, resolved, resolved_port, path, timeout, True, connector)
    except TargetError:
        raise
    except ssl.SSLError as exc:
        raise TargetError(f"TLS connection to {resolved.name} failed") from exc
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        raise TargetError(f"connection to {resolved.name}:{resolved_port} failed") from exc


def _once(
    scheme: str,
    resolved: ResolvedHost,
    port: int,
    path: str,
    timeout: float,
    verify: bool,
    connector: Connector | None,
) -> tuple[int, list[tuple[str, str]]]:
    if connector is not None:
        conn: Any = connector(scheme, resolved.name, port, timeout, verify)
    else:
        conn = open_http(scheme, resolved, port, timeout, verify)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        response.read(1024)
        return int(response.status), list(response.getheaders())
    finally:
        conn.close()


def _path(parts: SplitResult) -> str:
    path = parts.path or "/"
    target = f"{path}?{parts.query}" if parts.query else path
    if any(char in target for char in "\r\n\x00"):
        raise TargetError("URL path is not usable")
    return target


def _same_host(left: str, right: str) -> bool:
    return left.strip().rstrip(".").lower() == right.strip().rstrip(".").lower()


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
                parsed = int(raw.strip().strip('"'))
            except ValueError:
                return None
            if parsed < 0:
                return None
            return parsed
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
            tokens = body.split()
            return bool(tokens) and "*" not in tokens
    return False
