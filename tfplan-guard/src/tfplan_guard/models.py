from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


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
    path: str
    address: str
    remediation: str
    line: int = 1

    def to_dict(self) -> dict[str, str | int]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "address": self.address,
            "remediation": self.remediation,
            "line": self.line,
        }


@dataclass(frozen=True)
class ScanReport:
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    files_checked: int = 0

    def failing(self, threshold: Severity) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if meets_threshold(item.severity, threshold))


@dataclass(frozen=True)
class Resource:
    address: str
    type: str
    values: dict[str, Any]
    unknown: Any
    path: str
    line: int


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    description: str
    remediation: str
