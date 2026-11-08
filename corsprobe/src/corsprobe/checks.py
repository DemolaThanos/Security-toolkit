from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from corsprobe.models import Exchange, Finding, Severity, with_credentials
from corsprobe.origins import CANARY_HEADER

_DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_BASE = {
    "origin-reflection": Severity.HIGH,
    "null-origin": Severity.HIGH,
    "prefix-bypass": Severity.HIGH,
    "suffix-bypass": Severity.HIGH,
    "unescaped-dot": Severity.HIGH,
    "any-subdomain": Severity.MEDIUM,
    "http-origin": Severity.MEDIUM,
    "wildcard": Severity.LOW,
    "preflight-methods": Severity.LOW,
    "preflight-headers": Severity.LOW,
}
_SPECIFIC = (
    "null-origin",
    "prefix-bypass",
    "suffix-bypass",
    "unescaped-dot",
    "any-subdomain",
    "http-origin",
)


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    description: str
    remediation: str


RULES: tuple[Rule, ...] = (
    Rule(
        "origin-reflection",
        Severity.HIGH,
        "The server copies an arbitrary Origin into Access-Control-Allow-Origin.",
        "Allow only origins on an exact list. Do not copy the request Origin into the response.",
    ),
    Rule(
        "null-origin",
        Severity.HIGH,
        "The server allows the null origin.",
        "Do not allow the null origin. Sandboxed frames and data URLs send it.",
    ),
    Rule(
        "prefix-bypass",
        Severity.HIGH,
        "A trusted host is matched as a prefix of an attacker-controlled origin.",
        "Compare the origin host for equality. Do not use a starts-with check on the origin string.",
    ),
    Rule(
        "suffix-bypass",
        Severity.HIGH,
        "A trusted host is matched as a suffix without a dot boundary.",
        "Require a dot before the trusted domain, or compare the full host.",
    ),
    Rule(
        "unescaped-dot",
        Severity.HIGH,
        "A trusted host matches an origin the way an unescaped dot in a regular expression would.",
        "Escape dots in any regular expression, or compare hostnames without one.",
    ),
    Rule(
        "any-subdomain",
        Severity.MEDIUM,
        "Any subdomain of a trusted host is allowed.",
        "List the subdomains you intend to trust. A subdomain you do not control becomes a CORS bypass.",
    ),
    Rule(
        "http-origin",
        Severity.MEDIUM,
        "An https site trusts the same host over http.",
        "Do not trust an http origin for an https site.",
    ),
    Rule(
        "wildcard",
        Severity.LOW,
        "Access-Control-Allow-Origin is *.",
        "A wildcard lets any site read the response. Use an explicit origin if the data is not public.",
    ),
    Rule(
        "wildcard-credentials",
        Severity.MEDIUM,
        "Access-Control-Allow-Origin is * and credentials are allowed.",
        "Browsers ignore this pair. Drop the wildcard or the credentials flag. If you need credentials, list origins.",
    ),
    Rule(
        "preflight-methods",
        Severity.LOW,
        "A preflight allows methods beyond the safe set for an origin that is not restricted.",
        "Allow only the methods the route implements.",
    ),
    Rule(
        "preflight-headers",
        Severity.LOW,
        "A preflight allows arbitrary or credential-bearing headers for an origin that is not restricted.",
        "Allow only headers the application reads. Do not echo Access-Control-Request-Headers.",
    ),
)


def classify(target: str, exchanges: Sequence[Exchange]) -> tuple[Finding, ...]:
    usable = [item for item in exchanges if _countable(item)]
    resource = [item for item in usable if item.case_id != "preflight"]
    findings: list[Finding] = []
    wildcard = _pick_wildcard(resource)
    reflected = _arbitrary(resource)
    if wildcard is not None:
        findings.append(_finding(target, "wildcard", wildcard))
    if reflected is not None:
        findings.append(_finding(target, "origin-reflection", reflected))
    # A broader allow-origin covers a narrower one only when it already
    # includes credentials. Browsers ignore credentials on a wildcard, and a
    # preflight does not make the resource response readable.
    cover_credentials = reflected is not None and _credentials(reflected.headers)
    covered = reflected is not None or wildcard is not None
    for case_id in _SPECIFIC:
        hit = _first_exact(resource, case_id)
        if hit is None or _suppressed(hit, covered, cover_credentials):
            continue
        findings.append(_finding(target, case_id, hit))
    preflight = next((item for item in usable if item.case_id == "preflight"), None)
    if preflight is not None and _allows(preflight):
        findings.extend(_preflight(target, preflight))
    return tuple(findings)


def _countable(item: Exchange) -> bool:
    return item.status >= 200 and item.status not in _REDIRECT_STATUSES


def _suppressed(item: Exchange, covered: bool, cover_credentials: bool) -> bool:
    if not covered:
        return False
    return not (_credentials(item.headers) and not cover_credentials)


def _finding(target: str, rule_id: str, item: Exchange) -> Finding:
    credentials = _credentials(item.headers)
    final_rule, severity = _apply(rule_id, credentials)
    return Finding(
        rule_id=final_rule,
        severity=severity,
        target=target,
        origin=item.origin,
        message=_message(rule_id, item, credentials),
        credentials=credentials,
        final_url=item.final_url,
    )


def _apply(rule_id: str, credentials: bool) -> tuple[str, Severity]:
    base = _BASE[rule_id]
    if rule_id == "wildcard" and credentials:
        return "wildcard-credentials", with_credentials(base, True)
    return rule_id, with_credentials(base, credentials)


def _message(rule_id: str, item: Exchange, credentials: bool) -> str:
    if rule_id == "wildcard":
        if credentials:
            return "Access-Control-Allow-Origin is * and allows credentials; browsers ignore this pair"
        return "Access-Control-Allow-Origin is *"
    clause = " and allows credentials" if credentials else ""
    origin = item.origin
    host = item.host
    if rule_id == "origin-reflection":
        text = f"reflected {origin}"
    elif rule_id == "null-origin":
        text = "allowed the null origin"
    elif rule_id == "prefix-bypass":
        text = f"host {host} matched as a prefix of {origin}"
    elif rule_id == "suffix-bypass":
        text = f"host {host} matched as a suffix of {origin}"
    elif rule_id == "unescaped-dot":
        text = f"host {host} matched {origin} the way an unescaped dot would"
    elif rule_id == "any-subdomain":
        text = f"host {host} trusts subdomain {origin}"
    elif rule_id == "http-origin":
        text = f"https site trusts {origin}"
    else:
        text = origin
    return text + clause


def _preflight(target: str, item: Exchange) -> list[Finding]:
    found: list[Finding] = []
    methods = _dangerous_methods(item.headers)
    if methods:
        found.append(_preflight_finding(target, "preflight-methods", item, ", ".join(methods)))
    headers = _dangerous_headers(item.headers)
    if headers:
        found.append(_preflight_finding(target, "preflight-headers", item, ", ".join(headers)))
    return found


def _preflight_finding(target: str, rule_id: str, item: Exchange, shown: str) -> Finding:
    # Browsers reject a credentialed check when the allow-origin is *.
    credentials = _credentials(item.headers) and _acao(item) != "*"
    final_rule, severity = _apply(rule_id, credentials)
    clause = " and allows credentials" if credentials else ""
    if rule_id == "preflight-methods":
        message = f"preflight allows {shown}{clause}"
    else:
        message = f"preflight allows requested headers {shown}{clause}"
    return Finding(final_rule, severity, target, item.origin, message, credentials, item.final_url)


def _pick_wildcard(exchanges: Sequence[Exchange]) -> Exchange | None:
    found = [item for item in exchanges if _acao(item) == "*"]
    if not found:
        return None
    for item in found:
        if _credentials(item.headers):
            return item
    return found[0]


def _arbitrary(exchanges: Sequence[Exchange]) -> Exchange | None:
    for item in exchanges:
        if item.case_id == "origin-reflection" and _reflects(item):
            return item
    return None


def _first_exact(exchanges: Sequence[Exchange], case_id: str) -> Exchange | None:
    for item in exchanges:
        if item.case_id == case_id and _reflects(item):
            return item
    return None


def _allows(item: Exchange) -> bool:
    value = _acao(item)
    return value == "*" or value == item.origin


def _reflects(item: Exchange) -> bool:
    return _acao(item) == item.origin


def _acao(item: Exchange) -> str | None:
    values = _values(item.headers, "access-control-allow-origin")
    if len(values) != 1:
        return None
    return values[0]


def _credentials(headers: Sequence[tuple[str, str]]) -> bool:
    values = _values(headers, "access-control-allow-credentials")
    return len(values) == 1 and values[0] == "true"


def _dangerous_methods(headers: Sequence[tuple[str, str]]) -> tuple[str, ...]:
    found: list[str] = []
    for token in _tokens(headers, "access-control-allow-methods"):
        upper = token.upper()
        if upper == "*":
            return ("*",)
        if upper in _DANGEROUS_METHODS and upper not in found:
            found.append(upper)
    return tuple(found)


def _dangerous_headers(headers: Sequence[tuple[str, str]]) -> tuple[str, ...]:
    found: list[str] = []
    for token in _tokens(headers, "access-control-allow-headers"):
        lower = token.lower()
        if lower == "*":
            return ("*",)
        if lower in {CANARY_HEADER, "authorization"} and lower not in found:
            found.append(lower)
    return tuple(found)


def _tokens(headers: Sequence[tuple[str, str]], name: str) -> tuple[str, ...]:
    found: list[str] = []
    for value in _values(headers, name):
        for part in value.split(","):
            token = part.strip()
            if token and token not in found:
                found.append(token)
    return tuple(found)


def _values(headers: Sequence[tuple[str, str]], name: str) -> tuple[str, ...]:
    key = name.lower()
    return tuple(value.strip() for header, value in headers if header.lower() == key and value.strip())
