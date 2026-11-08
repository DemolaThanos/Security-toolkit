from __future__ import annotations

from dataclasses import dataclass
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

_LADDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        known = ", ".join(item.value for item in Severity)
        raise ValueError(f"unknown severity {value!r}; expected one of: {known}") from exc


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return _RANK[severity] >= _RANK[threshold]


def with_credentials(severity: Severity, credentials: bool) -> Severity:
    """One step higher when the same response allows credentials. Critical stays put."""
    if not credentials:
        return severity
    index = _LADDER.index(severity)
    return _LADDER[min(index + 1, len(_LADDER) - 1)]


@dataclass(frozen=True)
class Target:
    raw: str
    scheme: str
    host: str
    port: int | None
    path: str


@dataclass(frozen=True)
class Case:
    case_id: str
    origin: str
    host: str


@dataclass(frozen=True)
class Exchange:
    case_id: str
    origin: str
    host: str
    method: str
    status: int
    headers: tuple[tuple[str, str], ...]
    final_url: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    target: str
    origin: str
    message: str
    credentials: bool
    final_url: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "target": self.target,
            "origin": self.origin,
            "message": self.message,
            "credentials": self.credentials,
            "final_url": self.final_url,
        }


@dataclass(frozen=True)
class Failure:
    target: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "message": self.message}


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    errors: tuple[Failure, ...]
    targets_checked: int

    def failing(self, threshold: Severity) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if meets_threshold(item.severity, threshold))
