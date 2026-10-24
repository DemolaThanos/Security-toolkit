import socket
from datetime import UTC, datetime, timedelta

import pytest

from authrecon.audit import inspect
from authrecon.checks import header_findings, tls_findings
from authrecon.cli import main
from authrecon.errors import TargetError
from authrecon.http_client import fetch_headers
from authrecon.models import TlsInfo
from authrecon.net import HostClass, classify_host
from authrecon.ports import PortSpecError, parse_ports

GOOD = (
    ("strict-transport-security", "max-age=31536000; includeSubDomains"),
    ("content-security-policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none'"),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "geolocation=()"),
    ("cross-origin-opener-policy", "same-origin"),
)


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

    def request(self, method: str, path: str, headers: dict[str, str] | None = None, body: object = None) -> None:
        del method, path, headers, body

    def getresponse(self) -> _Response:
        return _Response(self._status, self._headers)

    def close(self) -> None:
        return None


def test_strict_headers_have_no_findings() -> None:
    findings, observations = header_findings(GOOD, scheme="https")
    assert findings == []
    assert observations == ["no rate-limit header on this response"]


def test_missing_controls_and_cookie() -> None:
    headers = (
        ("content-type", "text/html"),
        ("set-cookie", "sid=abc"),
        ("server", "cloudflare"),
        ("content-security-policy", "script-src 'unsafe-inline'"),
    )
    findings, observations = header_findings(headers, scheme="https")
    ids = {item.rule_id for item in findings}
    assert {"hsts-missing", "csp-unsafe", "cookie-secure", "x-content-type-options"} <= ids
    assert "Cloudflare header present" in observations


def test_tls_findings() -> None:
    info = TlsInfo(
        protocol="TLSv1.2",
        cipher="AES128-SHA",
        verified=True,
        verify_error=None,
        not_after=datetime.now(UTC) + timedelta(days=10),
        subject="example",
        legacy_accepted=("TLSv1",),
        legacy_unknown=(),
        handshake_error=None,
    )
    ids = {item.rule_id: item.severity.value for item in tls_findings(info)}
    assert ids["tls-legacy"] == "high"
    assert ids["cert-expiring"] == "medium"
    assert ids["tls-weak-cipher"] == "medium"


def test_expired_certificate() -> None:
    info = TlsInfo(
        protocol="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        verified=True,
        verify_error=None,
        not_after=datetime.now(UTC) - timedelta(days=1),
        subject=None,
        legacy_accepted=(),
        legacy_unknown=(),
        handshake_error=None,
    )
    assert any(item.rule_id == "cert-expired" for item in tls_findings(info))


def test_address_policy() -> None:
    with pytest.raises(TargetError, match="link-local"):
        classify_host("169.254.169.254")
    with pytest.raises(TargetError, match="non-routable"):
        classify_host("100.64.0.1")
    assert classify_host("10.1.1.1") is HostClass.PRIVATE
    assert classify_host("1.1.1.1") is HostClass.PUBLIC


def test_port_limits() -> None:
    assert parse_ports("8080-8082,443") == (8080, 8081, 8082, 443)
    with pytest.raises(PortSpecError):
        parse_ports("1-100")
    with pytest.raises(PortSpecError):
        parse_ports("0")


def test_redirect_to_metadata_is_not_followed() -> None:
    calls: list[str] = []

    def connector(scheme: str, host: str, port: int, timeout: float, verify: bool) -> _Conn:
        del scheme, port, timeout, verify
        calls.append(host)
        if host == "app.example":
            return _Conn(302, [("Location", "http://169.254.169.254/latest/meta-data/")])
        raise AssertionError(host)

    def fake_dns(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        addresses = {
            "app.example": "93.184.216.34",
            "169.254.169.254": "169.254.169.254",
        }
        ip = addresses[host]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkey = pytest.MonkeyPatch()
    monkey.setattr(socket, "getaddrinfo", fake_dns)
    try:
        with pytest.raises(TargetError, match="link-local"):
            fetch_headers("https://app.example/", timeout=1, connector=connector)
    finally:
        monkey.undo()
    assert calls == ["app.example"]


def test_inspect_uses_injected_results() -> None:
    class Fetched:
        final_url = "https://app.example/"
        status = 200
        headers = GOOD

    report = inspect(
        "https://app.example/",
        authorized=True,
        timeout=1,
        ports=(),
        fetcher=lambda url, timeout: Fetched(),
        tls_prober=lambda host, port, timeout: TlsInfo(
            "TLSv1.3",
            "TLS_AES_128_GCM_SHA256",
            True,
            None,
            datetime.now(UTC) + timedelta(days=90),
            "app.example",
            (),
            (),
            None,
        ),
    )
    assert report.findings == ()


def test_cli_requires_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def boom(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise AssertionError(args)

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert main(["inspect", "https://example.com"]) == 2
    assert calls == []


def test_authorization_does_not_override_address_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def connect(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise OSError("refused")

    monkeypatch.setenv("AUTHRECON_AUTHORIZED", "1")
    monkeypatch.setattr(socket, "create_connection", connect)
    assert main(["inspect", "http://169.254.169.254/"]) == 2
    assert calls == []


def test_redirects_stay_on_the_named_host(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def connector(scheme: str, host: str, port: int, timeout: float, verify: bool) -> _Conn:
        del scheme, port, timeout, verify
        calls.append(host)
        if len(calls) == 1:
            return _Conn(302, [("Location", "https://other.example/next")])
        return _Conn(200, list(GOOD))

    def fake_dns(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        addresses = {"app.example": "93.184.216.34", "other.example": "93.184.216.35"}
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addresses[host], 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
    with pytest.raises(TargetError, match="different host"):
        fetch_headers("https://app.example/", timeout=1, connector=connector)
    assert calls == ["app.example"]

    calls.clear()

    def same_host(scheme: str, host: str, port: int, timeout: float, verify: bool) -> _Conn:
        del scheme, port, timeout, verify
        calls.append(host)
        if len(calls) == 1:
            return _Conn(302, [("Location", "/next")])
        return _Conn(200, list(GOOD))

    result = fetch_headers("https://app.example/start", timeout=1, connector=same_host)
    assert result.status == 200
    assert calls == ["app.example", "app.example"]


def test_policy_failure_does_not_open_ports() -> None:
    def ports(*args: object, **kwargs: object) -> tuple[object, ...]:
        raise AssertionError(args)

    with pytest.raises(TargetError, match="link-local"):
        inspect("http://169.254.169.254/", authorized=True, timeout=1, ports=(80,), port_prober=ports)


def test_connect_failure_still_checks_the_named_ports() -> None:
    from authrecon.errors import ConnectError

    seen: list[tuple[int, ...]] = []

    def fetcher(url: str, timeout: float = 1) -> object:
        del url, timeout
        raise ConnectError("down")

    def ports(host: str, port_list: tuple[int, ...], timeout: float) -> tuple[object, ...]:
        del host, timeout
        seen.append(port_list)
        return ()

    report = inspect(
        "http://10.1.1.1/",
        authorized=True,
        timeout=1,
        ports=(8080,),
        fetcher=fetcher,
        port_prober=ports,
    )
    assert seen == [(8080,)]
    assert any(item.rule_id == "http-unreachable" for item in report.findings)


def test_port_banner_is_one_line(monkeypatch: pytest.MonkeyPatch) -> None:
    from authrecon.ports import probe_ports

    class Sock:
        def settimeout(self, value: float) -> None:
            del value

        def recv(self, amount: int) -> bytes:
            del amount
            return b"hello\x00world\n"

        def close(self) -> None:
            return None

    pauses: list[float] = []
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: Sock())
    results = probe_ports("127.0.0.1", (22, 23), 1, sleeper=pauses.append)
    assert pauses == [0.2]
    assert results[0].open is True
    assert results[0].banner == "hello world"
    assert "\n" not in results[0].banner
    assert "\x00" not in results[0].banner


def test_cookie_and_clickjacking_edges() -> None:
    findings, _observations = header_findings((("set-cookie", "sid=abc; SameSite=None"),), scheme="https")
    matched = [item for item in findings if item.rule_id == "cookie-samesite"]
    assert matched and matched[0].severity.value == "high"
    assert all("abc" not in item.message for item in findings)

    findings, _observations = header_findings(
        (("content-security-policy", "default-src 'self'; frame-ancestors"),),
        scheme="https",
    )
    assert any(item.rule_id == "clickjacking" for item in findings)

    findings, _observations = header_findings(
        (("strict-transport-security", "max-age=-1"), ("server", "nginx\nlow\tspoof")),
        scheme="https",
    )
    hsts = next(item for item in findings if item.rule_id == "hsts-max-age")
    assert "missing" in hsts.message
    server = next(item for item in findings if item.rule_id == "server-disclosure")
    assert "\n" not in server.message
    assert "spoof" in server.message


def test_timeout_is_checked_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def boom(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise AssertionError(args)

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert main(["inspect", "https://example.com", "--i-am-authorized", "--timeout", "nan"]) == 2
    assert calls == []
