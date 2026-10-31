from __future__ import annotations

from subtake.dns import QueryResult
from subtake.fingerprints import HttpRule, Service
from subtake.http_client import HttpSnapshot
from subtake.models import Verdict


class MapLookup:
    def __init__(self, records: dict[tuple[str, str], QueryResult]) -> None:
        self.records = records
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, rdtype: str) -> QueryResult:
        self.calls.append((name, rdtype))
        return self.records.get((name, rdtype), QueryResult())


class ScriptedProbe:
    def __init__(self, snapshot: HttpSnapshot) -> None:
        self.snapshot = snapshot
        self.calls: list[tuple[str, str, tuple[str, ...], float]] = []

    def probe(self, host: str, sni: str, addresses: tuple[str, ...], timeout: float) -> HttpSnapshot:
        self.calls.append((host, sni, addresses, timeout))
        return self.snapshot


GITHUB = Service(
    id="github-pages",
    service="GitHub Pages",
    cname=("*.github.io",),
    nxdomain=Verdict.LIKELY,
    on_miss=Verdict.EDGE,
    http=(HttpRule("There isn't a GitHub Pages site here", (404,), Verdict.LIKELY),),
)

S3 = Service(
    id="aws-s3",
    service="Amazon S3",
    cname=("*.s3.amazonaws.com",),
    nxdomain=Verdict.EDGE,
    on_miss=Verdict.SAFE,
    http=(HttpRule("NoSuchBucket", (404,), Verdict.LIKELY),),
)


def linked(
    host: str,
    target: str,
    *,
    addresses: tuple[str, ...] = ("93.184.216.34",),
    nxdomain: bool = False,
) -> MapLookup:
    records: dict[tuple[str, str], QueryResult] = {(host, "CNAME"): QueryResult(names=(target,))}
    if nxdomain:
        records[(target, "CNAME")] = QueryResult(nxdomain=True)
        return MapLookup(records)
    records[(target, "CNAME")] = QueryResult()
    records[(target, "A")] = QueryResult(names=addresses)
    records[(target, "AAAA")] = QueryResult()
    return MapLookup(records)
