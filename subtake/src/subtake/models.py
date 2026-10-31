from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from subtake.errors import SubtakeError


class Verdict(StrEnum):
    LIKELY = "likely-vulnerable"
    EDGE = "edge-case"
    SAFE = "not-vulnerable"


@dataclass(frozen=True)
class Result:
    host: str
    verdict: Verdict
    service: str | None
    fingerprint: str | None
    cname_chain: tuple[str, ...]
    http_status: int | None
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "verdict": self.verdict.value,
            "service": self.service,
            "fingerprint": self.fingerprint,
            "cname_chain": list(self.cname_chain),
            "http_status": self.http_status,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Report:
    results: tuple[Result, ...]

    def counts(self) -> tuple[int, int, int]:
        likely = sum(item.verdict is Verdict.LIKELY for item in self.results)
        edge = sum(item.verdict is Verdict.EDGE for item in self.results)
        safe = sum(item.verdict is Verdict.SAFE for item in self.results)
        return likely, edge, safe

    def issues(self) -> tuple[Result, ...]:
        return tuple(item for item in self.results if item.verdict is not Verdict.SAFE)

    def failing(self, fail_on: str) -> tuple[Result, ...]:
        if fail_on == "likely":
            wanted = {Verdict.LIKELY}
        elif fail_on == "edge":
            wanted = {Verdict.LIKELY, Verdict.EDGE}
        else:
            raise SubtakeError("fail-on must be likely or edge")
        return tuple(item for item in self.results if item.verdict in wanted)
