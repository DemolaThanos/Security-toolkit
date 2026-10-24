from __future__ import annotations

import json
import math
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

from authrecon.checks import header_findings, tls_findings
from authrecon.errors import ConnectError, PolicyError, TargetError
from authrecon.http_client import Connector, fetch_headers
from authrecon.models import Finding, PortResult, Report, Severity, TlsInfo
from authrecon.ports import probe_ports
from authrecon.tls import probe_tls


class HeaderResponse(Protocol):
    final_url: str
    status: int
    headers: tuple[tuple[str, str], ...]


def inspect(
    url: str,
    *,
    authorized: bool,
    timeout: float,
    ports: tuple[int, ...] = (),
    fetcher: Callable[..., HeaderResponse] | None = None,
    tls_prober: Callable[[str, int, float], TlsInfo] | None = None,
    port_prober: Callable[..., tuple[PortResult, ...]] | None = None,
    connector: Connector | None = None,
) -> Report:
    if not authorized:
        raise PolicyError(
            "refusing to run without --i-am-authorized. "
            "authrecon is for hosts you own or have written permission to test."
        )
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise TargetError("timeout must be between 0.1 and 30 seconds")
    if timeout < 0.1 or timeout > 30:
        raise TargetError("timeout must be between 0.1 and 30 seconds")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise TargetError("URL must be http or https and include a host")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    tls_info: TlsInfo | None = None
    if parts.scheme == "https":
        tls_info = (tls_prober or probe_tls)(host, port, timeout)
    http_error: str | None = None
    fetched: HeaderResponse | None
    try:
        if fetcher is not None:
            fetched = fetcher(url, timeout=timeout)
        else:
            fetched = fetch_headers(url, timeout=timeout, connector=connector)
    except ConnectError as exc:
        http_error = str(exc)
        fetched = None
    port_results: tuple[PortResult, ...] = ()
    if ports:
        port_results = (port_prober or probe_ports)(host, ports, timeout)
    if http_error is not None or fetched is None:
        findings = [Finding("http-unreachable", Severity.HIGH, http_error or "HTTP request failed")]
        if tls_info is not None:
            findings.extend(tls_findings(tls_info))
        return Report(url, None, None, tuple(findings), (), tls_info, port_results)
    final = str(fetched.final_url)
    status = fetched.status
    headers = fetched.headers
    if not isinstance(status, int) or not isinstance(headers, tuple):
        raise TargetError("HTTP result was incomplete")
    scheme = urlsplit(final).scheme
    findings, observations = header_findings(headers, scheme=scheme)
    if tls_info is not None:
        findings.extend(tls_findings(tls_info))
    return Report(
        url=url,
        final_url=final,
        status_code=status,
        findings=tuple(findings),
        observations=tuple(observations),
        tls=tls_info,
        ports=port_results,
    )


def render(report: Report, report_format: str) -> str:
    if report_format == "json":
        return json.dumps(report.to_dict(), indent=2) + "\n"
    lines: list[str] = []
    target = report.final_url or report.url
    status = "-" if report.status_code is None else str(report.status_code)
    lines.append(f"{target} status {status}")
    if report.tls and report.tls.protocol:
        lines.append(f"tls {report.tls.protocol} {report.tls.cipher or ''}".rstrip())
    for finding in report.findings:
        lines.append(f"{finding.severity.value}\t{finding.rule_id}\t{finding.message}")
    if report.observations:
        lines.append("observations: " + "; ".join(report.observations))
    if report.ports:
        shown = ", ".join(
            f"{item.port} {'open' if item.open else 'closed'}" + (f" {item.banner}" if item.banner else "")
            for item in report.ports
        )
        lines.append(f"ports: {shown}")
    lines.append(f"{len(report.findings)} findings")
    return "\n".join(lines) + "\n"
