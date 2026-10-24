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

_WORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def parse_severity(value: str) -> Severity:
    try:
        return _WORDS[value.strip().lower()]
    except KeyError as exc:
        known = ", ".join(item.value for item in Severity)
        raise ValueError(f"unknown severity {value!r}; expected one of: {known}") from exc


def severity_rank(severity: Severity) -> int:
    return _RANK[severity]


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return severity_rank(severity) >= severity_rank(threshold)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    tool: str
    path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "tool": self.tool,
            "path": self.path,
            "line": self.line,
        }


@dataclass(frozen=True)
class ScanReport:
    findings: tuple[Finding, ...]
    files_scanned: int

    def failing(self, threshold: Severity) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if meets_threshold(item.severity, threshold))
