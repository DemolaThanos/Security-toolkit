import socket

import pytest

from devsecops_scan.dast import evaluate_headers, fetch_headers, scan_dast
from devsecops_scan.errors import TargetError
from devsecops_scan.net import HostClass, classify_host


class _Response:
    def __init__(self, status: int, headers: list[tuple[str, str]]) -> None:
        self.status = status
        self._headers = headers

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers

    def read(self, amount: int = 0) -> bytes:
        del amount
        return b""


class _Conn:
    def __init__(self, status: int, headers: list[tuple[str, str]]) -> None:
        self._status = status
        self._headers = headers

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: object = None,
    ) -> None:
        del method, path, headers, body

    def getresponse(self) -> _Response:
        return _Response(self._status, self._headers)

    def close(self) -> None:
        return None


def test_authorization_and_metadata() -> None:
    def connector(*args: object, **kwargs: object) -> _Conn:
        raise AssertionError(args)

    with pytest.raises(TargetError, match="authorized"):
        scan_dast("https://example.com", authorized=False, timeout=1, connector=connector)
    with pytest.raises(TargetError, match="link-local"):
        fetch_headers("http://169.254.169.254/", timeout=1, connector=connector)


def test_header_gate() -> None:
    findings = evaluate_headers(
        (("content-type", "text/html; charset=utf-8"),),
        final_url="https://app.example/",
        scheme="https",
        content_type="text/html; charset=utf-8",
    )
    assert {item.rule_id for item in findings} >= {"hsts-missing", "csp-missing"}
    assert any(item.severity.value == "high" and item.rule_id == "csp-missing" for item in findings)


def test_redirect_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def connector(scheme: str, host: str, port: int, timeout: float, verify: bool) -> _Conn:
        del scheme, port, timeout, verify
        calls.append(host)
        return _Conn(302, [("Location", "http://169.254.169.254/latest/")])

    def fake_dns(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        ip = "93.184.216.34" if host == "app.example" else "169.254.169.254"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
    with pytest.raises(TargetError, match="link-local"):
        fetch_headers("https://app.example/health", timeout=1, connector=connector)
    assert calls == ["app.example"]


def test_classify_literals() -> None:
    assert classify_host("10.0.0.8") is HostClass.PRIVATE
    assert classify_host("8.8.8.8") is HostClass.PUBLIC
