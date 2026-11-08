from __future__ import annotations

import logging
import math
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Protocol

from corsprobe.checks import classify
from corsprobe.errors import InputError, ProbeFailure
from corsprobe.http_client import perform
from corsprobe.models import Case, Exchange, Failure, Finding, Report, Target
from corsprobe.net import parse_trusted, request_url
from corsprobe.origins import build_cases, preflight_headers

logger = logging.getLogger("corsprobe")


class Fetcher(Protocol):
    def fetch(
        self,
        case: Case,
        target: Target,
        *,
        timeout: float,
        follow_off_host: bool,
    ) -> Exchange: ...


class HttpFetcher:
    def fetch(
        self,
        case: Case,
        target: Target,
        *,
        timeout: float,
        follow_off_host: bool,
    ) -> Exchange:
        method = "OPTIONS" if case.case_id == "preflight" else "GET"
        extra = preflight_headers() if method == "OPTIONS" else ()
        status, headers, final_url = perform(
            request_url(target),
            method=method,
            origin=case.origin,
            timeout=timeout,
            follow_off_host=follow_off_host,
            extra_headers=extra,
        )
        logger.debug("%s %s %s -> %s", target.raw, method, case.case_id, status)
        return Exchange(case.case_id, case.origin, case.host, method, status, headers, final_url)


class Limiter:
    """Spaces request starts across every worker."""

    def __init__(
        self,
        per_second: float,
        *,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if isinstance(per_second, bool) or not isinstance(per_second, (int, float)) or not math.isfinite(per_second):
            raise InputError("rate must be between 0 and 20")
        if per_second < 0 or per_second > 20:
            raise InputError("rate must be between 0 and 20")
        self._gap = 0.0 if per_second == 0 else 1.0 / per_second
        if not math.isfinite(self._gap):
            raise InputError("rate must be between 0 and 20")
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


def scan(
    targets: Sequence[Target],
    *,
    trusted: str | None,
    timeout: float,
    concurrency: int,
    rate: float,
    preflight: bool,
    follow_off_host: bool,
    fetcher: Fetcher | None = None,
) -> Report:
    _bounds(timeout, concurrency, rate)
    trusted_host = parse_trusted(trusted) if trusted else None
    if isinstance(targets, str) or not targets:
        raise InputError("no URLs to scan")
    client: Fetcher = fetcher if fetcher is not None else HttpFetcher()
    pace = Limiter(rate)
    results: list[tuple[tuple[Finding, ...], Failure | None]] = [((), None) for _ in targets]
    workers = min(concurrency, len(targets))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_one, target, trusted_host, timeout, preflight, follow_off_host, client, pace): index
            for index, target in enumerate(targets)
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    findings: list[Finding] = []
    errors: list[Failure] = []
    for found, failure in results:
        findings.extend(found)
        if failure is not None:
            errors.append(failure)
    logger.info("checked %s targets: %s findings, %s errors", len(targets), len(findings), len(errors))
    return Report(tuple(findings), tuple(errors), len(targets))


def _one(
    target: Target,
    trusted: str | None,
    timeout: float,
    preflight: bool,
    follow_off_host: bool,
    client: Fetcher,
    pace: Limiter,
) -> tuple[tuple[Finding, ...], Failure | None]:
    try:
        return _assess(target, trusted, timeout, preflight, follow_off_host, client, pace), None
    except ProbeFailure as exc:
        logger.info("probe failed for %s: %s", target.raw, exc)
        return (), Failure(target.raw, str(exc))
    except Exception:
        logger.debug("check failed for %s", target.raw, exc_info=True)
        return (), Failure(target.raw, "check failed")


def _assess(
    target: Target,
    trusted: str | None,
    timeout: float,
    preflight: bool,
    follow_off_host: bool,
    client: Fetcher,
    pace: Limiter,
) -> tuple[Finding, ...]:
    exchanges: list[Exchange] = []
    for case in build_cases(target, trusted, preflight=preflight):
        pace.wait()
        exchanges.append(client.fetch(case, target, timeout=timeout, follow_off_host=follow_off_host))
    return classify(target.raw, exchanges)


def _bounds(timeout: float, concurrency: int, rate: float) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise InputError("timeout must be between 0.1 and 30 seconds")
    if not 0.1 <= float(timeout) <= 30:
        raise InputError("timeout must be between 0.1 and 30 seconds")
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or not 1 <= concurrency <= 8:
        raise InputError("concurrency must be an integer between 1 and 8")
    Limiter(rate)
