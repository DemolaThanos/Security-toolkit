from __future__ import annotations

import logging
import math
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed

from subtake.dns import Chain, Lookup, QueryResult, resolve_chain
from subtake.errors import SubtakeError
from subtake.fingerprints import Service, match_name, matching_rule
from subtake.http_client import HttpProber, HttpSnapshot
from subtake.models import Report, Result, Verdict
from subtake.net import normalize_hostname, public_addresses

logger = logging.getLogger("subtake")

_MAX_HOSTS = 10_000


class Limiter:
    """Spaces DNS and HTTP starts across every worker."""

    def __init__(
        self,
        per_second: float,
        *,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if isinstance(per_second, bool) or not isinstance(per_second, (int, float)) or not math.isfinite(per_second):
            raise SubtakeError("rate must be between 0 and 50")
        if per_second < 0:
            raise SubtakeError("rate must be between 0 and 50")
        self._gap = 0.0 if per_second == 0 else 1.0 / per_second
        self._now = time.monotonic if now is None else now
        self._sleep = time.sleep if sleep is None else sleep
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self._gap == 0:
            return
        with self._lock:
            current = self._now()
            delay = self._next - current
            if delay < 0:
                delay = 0.0
            self._next = current + delay + self._gap
        if delay > 0:
            self._sleep(delay)


class _LimitedLookup:
    def __init__(self, inner: Lookup, limiter: Limiter) -> None:
        self._inner = inner
        self._limiter = limiter

    def query(self, name: str, rdtype: str) -> QueryResult:
        self._limiter.wait()
        return self._inner.query(name, rdtype)


def check_hosts(
    hosts: Sequence[str],
    *,
    lookup: Lookup,
    prober: HttpProber,
    services: tuple[Service, ...],
    timeout: float,
    concurrency: int,
    rate: float,
) -> Report:
    _bounds(timeout, concurrency, rate)
    if isinstance(hosts, str) or not hosts:
        raise SubtakeError("no hostnames in input")
    if len(hosts) > _MAX_HOSTS:
        raise SubtakeError(f"more than {_MAX_HOSTS} hostnames")
    names = tuple(normalize_hostname(host) for host in hosts)
    pace = Limiter(rate)
    wrapped = _LimitedLookup(lookup, pace)
    results = [_failed(name) for name in names]
    workers = min(concurrency, len(names))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(assess, name, wrapped, prober, services, timeout, pace): index
            for index, name in enumerate(names)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception:
                logger.debug("failed checking %s", names[index], exc_info=True)
                results[index] = _failed(names[index])
    report = Report(tuple(results))
    likely, edge, safe = report.counts()
    logger.info(
        "checked %s hosts: %s likely-vulnerable, %s edge-case, %s not-vulnerable",
        len(report.results),
        likely,
        edge,
        safe,
    )
    return report


def assess(
    host: str,
    lookup: Lookup,
    prober: HttpProber,
    services: tuple[Service, ...],
    timeout: float,
    limiter: Limiter,
) -> Result:
    chain = resolve_chain(host, lookup)
    if chain.missing:
        return _result(host, Verdict.SAFE, None, chain, "name does not resolve", None)
    if chain.error:
        service = match_name(chain.cnames[-1], services) if chain.cnames else None
        return _result(host, Verdict.EDGE, service, chain, chain.error, None)
    if not chain.cnames:
        return _result(host, Verdict.SAFE, None, chain, "no CNAME", None)

    terminal = chain.cnames[-1]
    service = match_name(terminal, services)
    if chain.terminal_nxdomain:
        if service is None:
            detail = "target does not resolve and is not a tracked service"
            return _result(host, Verdict.EDGE, None, chain, detail, None)
        return _result(host, service.nxdomain, service, chain, f"{terminal} does not resolve", None)
    if service is None:
        return _result(host, Verdict.SAFE, None, chain, "not a tracked service", None)
    if not chain.addresses:
        return _result(host, Verdict.EDGE, service, chain, f"{terminal} has no address", None)
    targets = public_addresses(chain.addresses)
    if not targets:
        return _result(host, Verdict.EDGE, service, chain, "refusing non-public address", None)

    limiter.wait()
    snapshot = prober.probe(host, terminal, targets, timeout)
    return _from_http(host, service, chain, snapshot)


def _from_http(host: str, service: Service, chain: Chain, snapshot: HttpSnapshot) -> Result:
    if snapshot.status is None:
        detail = f"HTTP probe failed ({snapshot.error})" if snapshot.error else "HTTP probe failed"
        return _result(host, Verdict.EDGE, service, chain, detail, None)
    rule = matching_rule(service, snapshot.status, snapshot.body)
    if rule is not None:
        return _result(
            host,
            rule.verdict,
            service,
            chain,
            f"HTTP {snapshot.status} matched {service.service}",
            snapshot.status,
        )
    if 200 <= snapshot.status < 400:
        return _result(host, Verdict.SAFE, service, chain, f"HTTP {snapshot.status} looks live", snapshot.status)
    if service.on_miss is Verdict.EDGE:
        return _result(
            host,
            Verdict.EDGE,
            service,
            chain,
            f"HTTP {snapshot.status} did not match {service.service}",
            snapshot.status,
        )
    return _result(
        host,
        Verdict.SAFE,
        service,
        chain,
        f"HTTP {snapshot.status} did not match {service.service}",
        snapshot.status,
    )


def _result(
    host: str,
    verdict: Verdict,
    service: Service | None,
    chain: Chain,
    detail: str,
    status: int | None,
) -> Result:
    text = " ".join(detail.split())
    if chain.cnames:
        text = f"{' -> '.join((host, *chain.cnames))}; {text}"
    return Result(
        host=host,
        verdict=verdict,
        service=None if service is None else service.service,
        fingerprint=None if service is None else service.id,
        cname_chain=chain.cnames,
        http_status=status,
        evidence=text,
    )


def _failed(host: str) -> Result:
    return Result(host, Verdict.EDGE, None, None, (), None, "check failed")


def _bounds(timeout: float, concurrency: int, rate: float) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise SubtakeError("timeout must be between 0.1 and 30 seconds")
    if timeout < 0.1 or timeout > 30:
        raise SubtakeError("timeout must be between 0.1 and 30 seconds")
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or not 1 <= concurrency <= 32:
        raise SubtakeError("concurrency must be an integer between 1 and 32")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate):
        raise SubtakeError("rate must be between 0 and 50")
    if rate < 0 or rate > 50:
        raise SubtakeError("rate must be between 0 and 50")
