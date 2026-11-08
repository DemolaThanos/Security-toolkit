"""Origin values sent for one target. Every value is a header. None of them is dialed."""

from __future__ import annotations

from corsprobe.errors import InputError
from corsprobe.models import Case, Target
from corsprobe.net import format_origin, is_dns_name, normalize_hostname

ARBITRARY_ORIGIN = "https://corsprobe.invalid"
PREFLIGHT_METHOD = "DELETE"
PREFLIGHT_HEADER = "X-Corsprobe-Canary, Authorization"
CANARY_HEADER = "x-corsprobe-canary"
_MAX_CASES = 16


def build_cases(target: Target, trusted: str | None, *, preflight: bool) -> tuple[Case, ...]:
    cases = [
        Case("origin-reflection", ARBITRARY_ORIGIN, ""),
        Case("null-origin", "null", ""),
    ]
    if target.scheme == "https":
        cases.append(Case("http-origin", format_origin("http", target.host, target.port), ""))
    references: list[str] = []
    if is_dns_name(target.host):
        references.append(target.host)
    if trusted and trusted not in references:
        references.append(trusted)
    for host in references:
        cases.extend(_bypasses(host, target.port))
    if preflight:
        cases.append(Case("preflight", ARBITRARY_ORIGIN, ""))
    unique = _dedupe(cases)
    if len(unique) > _MAX_CASES:
        raise InputError("too many probes for one URL")
    return tuple(unique)


def preflight_headers() -> tuple[tuple[str, str], ...]:
    return (
        ("Access-Control-Request-Method", PREFLIGHT_METHOD),
        ("Access-Control-Request-Headers", PREFLIGHT_HEADER),
    )


def _bypasses(host: str, port: int | None) -> list[Case]:
    found: list[Case] = []
    prefix = f"{host}.corsprobe.invalid"
    if _usable(prefix):
        found.append(Case("prefix-bypass", f"https://{prefix}", host))
    suffix = f"not{host}"
    if _usable(suffix):
        found.append(Case("suffix-bypass", f"https://{suffix}", host))
    if "." in host:
        swapped = host.replace(".", "x", 1)
        if _usable(swapped):
            found.append(Case("unescaped-dot", f"https://{swapped}", host))
    child = f"corsprobe.{host}"
    if _usable(child):
        found.append(Case("any-subdomain", format_origin("https", child, port), host))
    return found


def _usable(host: str) -> bool:
    try:
        normalize_hostname(host)
    except InputError:
        return False
    return True


def _dedupe(cases: list[Case]) -> list[Case]:
    seen: set[tuple[str, str]] = set()
    unique: list[Case] = []
    for case in cases:
        key = (case.case_id, case.origin)
        if key in seen:
            continue
        seen.add(key)
        unique.append(case)
    return unique
