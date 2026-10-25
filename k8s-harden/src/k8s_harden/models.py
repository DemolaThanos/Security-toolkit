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
    location: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "location": self.location,
        }


@dataclass(frozen=True)
class LintReport:
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    files_checked: int = 0

    def failing(self, threshold: Severity) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if meets_threshold(item.severity, threshold))
