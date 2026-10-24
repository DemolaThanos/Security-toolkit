from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        known = ", ".join(item.value for item in Severity)
        raise ValueError(f"unknown severity {value!r}; expected one of: {known}") from exc


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return _RANK[severity] >= _RANK[threshold]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "severity": self.severity.value, "message": self.message}


@dataclass(frozen=True)
class TlsInfo:
    protocol: str | None
    cipher: str | None
    verified: bool
    verify_error: str | None
    not_after: datetime | None
    subject: str | None
    legacy_accepted: tuple[str, ...]
    legacy_unknown: tuple[str, ...]
    handshake_error: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "cipher": self.cipher,
            "verified": self.verified,
            "verify_error": self.verify_error,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "subject": self.subject,
            "legacy_accepted": list(self.legacy_accepted),
            "legacy_unknown": list(self.legacy_unknown),
            "handshake_error": self.handshake_error,
        }


@dataclass(frozen=True)
class PortResult:
    port: int
    open: bool
    banner: str

    def to_dict(self) -> dict[str, object]:
        return {"port": self.port, "open": self.open, "banner": self.banner}


@dataclass(frozen=True)
class Report:
    url: str
    final_url: str | None
    status_code: int | None
    findings: tuple[Finding, ...]
    observations: tuple[str, ...]
    tls: TlsInfo | None
    ports: tuple[PortResult, ...]

    def failing(self, threshold: Severity) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if meets_threshold(item.severity, threshold))

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "findings": [item.to_dict() for item in self.findings],
            "observations": list(self.observations),
            "tls": None if self.tls is None else self.tls.to_dict(),
            "ports": [item.to_dict() for item in self.ports],
        }
