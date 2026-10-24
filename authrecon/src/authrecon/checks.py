from __future__ import annotations

from datetime import UTC, datetime, timedelta

from authrecon.models import Finding, Severity, TlsInfo

_SECURE_REFERRER = frozenset(
    {
        "no-referrer",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)

_RATE_HEADERS = frozenset({"ratelimit-limit", "retry-after", "x-ratelimit-limit", "x-rate-limit-limit"})


def header_findings(
    headers: tuple[tuple[str, str], ...],
    *,
    scheme: str,
) -> tuple[list[Finding], list[str]]:
    grouped = _group(headers)
    findings: list[Finding] = []
    content_type = _one(grouped, "content-type") or ""
    html = content_type.split(";", 1)[0].strip().lower() == "text/html"

    if scheme != "https":
        findings.append(Finding("not-https", Severity.HIGH, "final response is not HTTPS"))
    else:
        _hsts(grouped, findings)

    csp = _one(grouped, "content-security-policy")
    if csp is None:
        findings.append(
            Finding(
                "csp-missing",
                Severity.HIGH if html else Severity.MEDIUM,
                "Content-Security-Policy is absent",
            )
        )
    else:
        _csp_unsafe(csp, findings)
    xcto = _one(grouped, "x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        findings.append(Finding("x-content-type-options", Severity.MEDIUM, "X-Content-Type-Options is not nosniff"))
    if not _clickjacking_ok(grouped, csp):
        findings.append(
            Finding(
                "clickjacking",
                Severity.MEDIUM,
                "no X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors",
            )
        )
    _referrer(grouped, findings)
    if _one(grouped, "permissions-policy") is None:
        findings.append(Finding("permissions-policy", Severity.LOW, "Permissions-Policy is absent"))
    coop = _one(grouped, "cross-origin-opener-policy")
    if coop is None or coop.strip().lower() == "unsafe-none":
        findings.append(Finding("coop-missing", Severity.LOW, "Cross-Origin-Opener-Policy is absent or unsafe-none"))
    _cookies(grouped, scheme, findings)
    server = _one(grouped, "server")
    if server:
        findings.append(Finding("server-disclosure", Severity.INFO, f"Server header discloses {_snippet(server)}"))
    powered = _one(grouped, "x-powered-by")
    if powered:
        findings.append(Finding("x-powered-by", Severity.INFO, f"X-Powered-By discloses {_snippet(powered)}"))
    return findings, _observations(grouped)


def tls_findings(info: TlsInfo, *, now: datetime | None = None) -> list[Finding]:
    current = now or datetime.now(UTC)
    findings: list[Finding] = []
    if info.handshake_error and info.protocol is None:
        findings.append(Finding("tls-handshake-failed", Severity.HIGH, info.handshake_error))
        return findings
    if info.protocol and info.protocol not in {"TLSv1.2", "TLSv1.3"}:
        findings.append(Finding("tls-old-protocol", Severity.HIGH, f"negotiated {info.protocol}"))
    if not info.verified:
        detail = info.verify_error or "certificate verification failed"
        findings.append(Finding("tls-verify-failed", Severity.HIGH, detail[:240]))
    for protocol in info.legacy_accepted:
        findings.append(Finding("tls-legacy", Severity.HIGH, f"server accepted {protocol}"))
    for protocol in info.legacy_unknown:
        findings.append(Finding("tls-legacy-unknown", Severity.INFO, f"could not confirm {protocol} is disabled"))
    if info.cipher and _weak_cipher(info.cipher):
        severity = Severity.HIGH if _broken_cipher(info.cipher) else Severity.MEDIUM
        findings.append(Finding("tls-weak-cipher", severity, f"negotiated cipher {info.cipher}"))
    if info.not_after is not None:
        remaining = info.not_after - current
        if remaining <= timedelta(0):
            expired = info.not_after.isoformat()
            findings.append(Finding("cert-expired", Severity.CRITICAL, f"certificate expired {expired}"))
        elif remaining <= timedelta(days=30):
            findings.append(
                Finding("cert-expiring", Severity.MEDIUM, f"certificate expires {info.not_after.isoformat()}")
            )
    return findings


def _hsts(grouped: dict[str, list[str]], findings: list[Finding]) -> None:
    hsts = _one(grouped, "strict-transport-security")
    if hsts is None:
        findings.append(Finding("hsts-missing", Severity.HIGH, "Strict-Transport-Security is absent"))
        return
    max_age, directives = _parse_hsts(hsts)
    if max_age is None or max_age < 15_552_000:
        shown = "missing" if max_age is None else str(max_age)
        findings.append(Finding("hsts-max-age", Severity.MEDIUM, f"HSTS max-age is {shown}; use at least 15552000"))
    if "includesubdomains" not in directives:
        findings.append(Finding("hsts-subdomains", Severity.LOW, "HSTS does not include subdomains"))


def _csp_unsafe(csp: str, findings: list[Finding]) -> None:
    directives = _csp(csp)
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        findings.append(Finding("csp-weak", Severity.MEDIUM, "CSP sets neither script-src nor default-src"))
        return
    lowered = script.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        findings.append(Finding("csp-unsafe", Severity.MEDIUM, "CSP allows unsafe-inline or unsafe-eval for scripts"))


def _referrer(grouped: dict[str, list[str]], findings: list[Finding]) -> None:
    value = _one(grouped, "referrer-policy")
    if value is None:
        findings.append(Finding("referrer-policy", Severity.MEDIUM, "Referrer-Policy is absent"))
        return
    policy = value.split(",")[0].strip().lower()
    if policy == "unsafe-url":
        findings.append(Finding("referrer-policy", Severity.HIGH, "Referrer-Policy is unsafe-url"))
    elif policy == "no-referrer-when-downgrade":
        findings.append(Finding("referrer-policy", Severity.LOW, "Referrer-Policy is the legacy downgrade value"))
    elif policy not in _SECURE_REFERRER:
        findings.append(
            Finding(
                "referrer-policy",
                Severity.MEDIUM,
                f"Referrer-Policy {_snippet(policy, 40)} is not a strict policy",
            )
        )


def _cookies(grouped: dict[str, list[str]], scheme: str, findings: list[Finding]) -> None:
    for raw in grouped.get("set-cookie", []):
        name, flags, attrs = _cookie(raw)
        name = _snippet(name, 80) or "<cookie>"
        if scheme == "https" and "secure" not in flags:
            findings.append(Finding("cookie-secure", Severity.HIGH, f"cookie {name} is missing Secure"))
        if "httponly" not in flags:
            findings.append(Finding("cookie-httponly", Severity.MEDIUM, f"cookie {name} is missing HttpOnly"))
        samesite = attrs.get("samesite", "").lower()
        if samesite == "none" and "secure" not in flags:
            findings.append(
                Finding("cookie-samesite", Severity.HIGH, f"cookie {name} sets SameSite=None without Secure")
            )
        elif "samesite" not in flags:
            findings.append(Finding("cookie-samesite", Severity.MEDIUM, f"cookie {name} is missing SameSite"))
        elif samesite not in {"strict", "lax", "none"}:
            shown = _snippet(samesite, 40)
            findings.append(Finding("cookie-samesite", Severity.MEDIUM, f"cookie {name} has SameSite {shown}"))


def _observations(grouped: dict[str, list[str]]) -> list[str]:
    notes: list[str] = []
    server = (_one(grouped, "server") or "").lower()
    if "cloudflare" in server or "cf-ray" in grouped:
        notes.append("Cloudflare header present")
    if "x-amzn-waf-action" in grouped:
        notes.append("AWS WAF header present")
    if "x-azure-ref" in grouped:
        notes.append("Azure Front Door header present")
    if "akamai" in server or any(key.startswith("x-akamai") for key in grouped):
        notes.append("Akamai header present")
    if _RATE_HEADERS & set(grouped):
        notes.append("rate-limit header present")
    else:
        notes.append("no rate-limit header on this response")
    return notes


def _clickjacking_ok(grouped: dict[str, list[str]], csp: str | None) -> bool:
    xfo = _one(grouped, "x-frame-options")
    if xfo is not None and xfo.strip().lower() in {"deny", "sameorigin"}:
        return True
    if xfo is not None and xfo.strip().lower().startswith("allow-from"):
        return False
    if csp is None:
        return False
    directives = _csp(csp)
    ancestors = directives.get("frame-ancestors")
    if not ancestors or not ancestors.split():
        return False
    return "*" not in ancestors.split()


def _parse_hsts(value: str) -> tuple[int | None, set[str]]:
    directives: set[str] = set()
    max_age: int | None = None
    for part in value.split(";"):
        item = part.strip()
        if not item:
            continue
        if item.lower().startswith("max-age"):
            _, _, raw = item.partition("=")
            try:
                parsed = int(raw.strip().strip('"'))
            except ValueError:
                max_age = None
            else:
                max_age = None if parsed < 0 else parsed
        else:
            directives.add(item.lower())
    return max_age, directives


def _csp(value: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in value.split(";"):
        item = part.strip()
        if not item:
            continue
        bits = item.split(None, 1)
        directives[bits[0].lower()] = bits[1] if len(bits) > 1 else ""
    return directives


def _cookie(raw: str) -> tuple[str, set[str], dict[str, str]]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else "<cookie>"
    flags: set[str] = set()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            flags.add(key.strip().lower())
            attrs[key.strip().lower()] = value.strip()
        else:
            flags.add(part.lower())
    return name, flags, attrs


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


def _snippet(value: str, limit: int = 80) -> str:
    cleaned = "".join(char if char.isprintable() else " " for char in value)
    return " ".join(cleaned.split())[:limit]


def _broken_cipher(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in ("NULL", "EXPORT", "RC4", "DES-CBC3", "3DES", "ANON", "MD5"))


def _weak_cipher(name: str) -> bool:
    upper = name.upper()
    if _broken_cipher(name):
        return True
    return upper.endswith("_SHA") or upper.endswith("-SHA")
