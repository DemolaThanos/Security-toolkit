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

SENSITIVE = frozenset({"credential", "payment", "pii", "phi", "secret", "session", "token"})
PROTECTED = frozenset({"https", "mtls", "sftp", "ssh", "tls", "wss"})


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return _RANK[severity] >= _RANK[threshold]


def parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        known = ", ".join(item.value for item in Severity)
        raise ValueError(f"unknown severity {value!r}; expected one of: {known}") from exc


@dataclass(frozen=True)
class Zone:
    id: str
    description: str
    external: bool


@dataclass(frozen=True)
class Component:
    id: str
    type: str
    zone: str
    description: str
    logs_actions: bool | None
    rate_limited: bool | None
    encrypted_at_rest: bool | None
    data_classes: tuple[str, ...]


@dataclass(frozen=True)
class Flow:
    id: str
    source: str
    destination: str
    protocol: str
    authenticated: bool
    data_classes: tuple[str, ...]


@dataclass(frozen=True)
class Model:
    name: str
    description: str
    zones: tuple[Zone, ...]
    components: tuple[Component, ...]
    flows: tuple[Flow, ...]

    def component(self, identifier: str) -> Component:
        for item in self.components:
            if item.id == identifier:
                return item
        raise KeyError(identifier)

    def zone(self, identifier: str) -> Zone:
        for item in self.zones:
            if item.id == identifier:
                return item
        raise KeyError(identifier)


@dataclass(frozen=True)
class Threat:
    id: str
    category: str
    element: str
    severity: Severity
    detail: str
    mitigation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "category": self.category,
            "element": self.element,
            "severity": self.severity.value,
            "detail": self.detail,
            "mitigation": self.mitigation,
        }
