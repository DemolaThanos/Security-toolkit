from __future__ import annotations

import threading

import pytest

from corsprobe.errors import InputError, ProbeFailure
from corsprobe.models import Case, Exchange, Target
from corsprobe.net import parse_target
from corsprobe.probe import Limiter, scan


class _Fetcher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, float, bool]] = []
        self.event = threading.Event()

    def fetch(self, case: Case, target: Target, *, timeout: float, follow_off_host: bool) -> Exchange:
        self.calls.append((target.raw, case.case_id, timeout, follow_off_host))
        if "slow" in target.raw and case.case_id == "origin-reflection":
            assert self.event.wait(2)
        elif case.case_id == "origin-reflection" and "fast" in target.raw:
            self.event.set()
        headers: tuple[tuple[str, str], ...] = ()
        if case.case_id == "origin-reflection" and "down" not in target.raw:
            headers = (("Access-Control-Allow-Origin", case.origin),)
        if "down" in target.raw:
            raise ProbeFailure("timed out")
        if "boom" in target.raw:
            raise RuntimeError("nope")
        return Exchange(case.case_id, case.origin, case.host, "GET", 200, headers, target.raw)


def test_results_keep_input_order() -> None:
    fetcher = _Fetcher()
    report = scan(
        (parse_target("https://slow.example/"), parse_target("https://fast.example/")),
        trusted=None,
        timeout=1,
        concurrency=2,
        rate=0,
        preflight=False,
        follow_off_host=True,
        fetcher=fetcher,
    )
    assert [item.target for item in report.findings] == ["https://slow.example/", "https://fast.example/"]
    assert fetcher.calls[0][2] == 1
    assert fetcher.calls[0][3] is True
    assert report.errors == ()


def test_a_failed_target_does_not_hide_the_other() -> None:
    report = scan(
        (parse_target("https://app.example/"), parse_target("https://down.example/")),
        trusted=None,
        timeout=1,
        concurrency=1,
        rate=0,
        preflight=False,
        follow_off_host=False,
        fetcher=_Fetcher(),
    )
    assert [item.target for item in report.findings] == ["https://app.example/"]
    assert report.errors == (report.errors[0],)
    assert report.errors[0].target == "https://down.example/"
    assert report.errors[0].message == "timed out"


def test_unexpected_errors_are_reported() -> None:
    report = scan(
        (parse_target("https://boom.example/"),),
        trusted=None,
        timeout=1,
        concurrency=1,
        rate=0,
        preflight=False,
        follow_off_host=False,
        fetcher=_Fetcher(),
    )
    assert report.findings == ()
    assert report.errors[0].message == "check failed"


def test_bounds() -> None:
    target = (parse_target("https://app.example/"),)
    with pytest.raises(InputError, match="timeout"):
        scan(target, trusted=None, timeout=float("nan"), concurrency=1, rate=0, preflight=False, follow_off_host=False)
    with pytest.raises(InputError, match="concurrency"):
        scan(
            target,
            trusted=None,
            timeout=1,
            concurrency=True,
            rate=0,
            preflight=False,
            follow_off_host=False,
        )
    with pytest.raises(InputError, match="no URLs"):
        scan((), trusted=None, timeout=1, concurrency=1, rate=0, preflight=False, follow_off_host=False)


def test_limiter_spaces_starts() -> None:
    slept: list[float] = []
    limiter = Limiter(2, now=lambda: 0.0, sleep=slept.append)
    limiter.wait()
    limiter.wait()
    assert slept == [0.5]
    quiet = Limiter(0, now=lambda: 0.0, sleep=slept.append)
    quiet.wait()
    assert slept == [0.5]
    with pytest.raises(InputError):
        Limiter(-1)
    with pytest.raises(InputError):
        Limiter(float("inf"))
