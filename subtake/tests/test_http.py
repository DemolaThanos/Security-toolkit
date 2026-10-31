from __future__ import annotations

import socket
import ssl

import pytest

from subtake.http_client import USER_AGENT, HttpProber, RefusedAddress, open_connection

PUBLIC = "93.184.216.34"


class _Raw:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Context:
    def __init__(self) -> None:
        self.check_hostname = False
        self.verify_mode = ssl.CERT_NONE

    def wrap_socket(self, sock: object, server_hostname: str | None = None) -> object:
        self.sni = server_hostname
        self.seen_sock = sock
        return sock


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body
        self.amount = 0

    def read(self, amount: int) -> bytes:
        self.amount = amount
        return self._body[:amount]


class _Conn:
    def __init__(self, status: int, body: bytes) -> None:
        self._status = status
        self._body = body
        self.headers: dict[str, str] | None = None
        self.method = ""
        self.path = ""
        self.closed = False
        self.response = _Response(status, body)

    def request(self, method: str, path: str, headers: dict[str, str] | None = None, body: object = None) -> None:
        del body
        self.method = method
        self.path = path
        self.headers = headers

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


def test_opener_refuses_non_public_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    def connect(*args: object, **kwargs: object) -> object:
        raise AssertionError(args)

    monkeypatch.setattr(socket, "create_connection", connect)
    for ip in ("10.1.1.1", "169.254.169.254", "::ffff:169.254.169.254", "127.0.0.1"):
        with pytest.raises(RefusedAddress):
            open_connection("http", ip, "example.com", 1)
        with pytest.raises(RefusedAddress):
            open_connection("https", ip, "example.com", 1)


def test_https_pins_the_address_and_verifies_the_provider_name(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    raw = _Raw()

    def connect(address: tuple[str, int], timeout: float) -> _Raw:
        seen["address"] = address
        seen["timeout"] = timeout
        return raw

    context = _Context()
    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    conn = open_connection("https", PUBLIC, "user.github.io", 2)
    assert seen["address"] == (PUBLIC, 443)
    assert seen["timeout"] == 2
    assert context.sni == "user.github.io"
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert conn.sock is raw
    assert raw.closed is False


def test_tls_failure_closes_the_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _Raw()

    class Broken:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, sock: object, server_hostname: str | None = None) -> object:
            del sock, server_hostname
            raise ssl.SSLError("bad")

    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: raw)
    monkeypatch.setattr(ssl, "create_default_context", lambda: Broken())
    with pytest.raises(ssl.SSLError):
        open_connection("https", PUBLIC, "user.github.io", 1)
    assert raw.closed is True


def test_http_uses_port_80(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def connect(address: tuple[str, int], timeout: float) -> _Raw:
        del timeout
        seen["address"] = address
        return _Raw()

    monkeypatch.setattr(socket, "create_connection", connect)
    conn = open_connection("http", PUBLIC, "example.com", 1)
    assert seen["address"] == (PUBLIC, 80)
    assert conn.sock is not None


def test_unsupported_scheme_does_not_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError()))
    with pytest.raises(RefusedAddress):
        open_connection("ftp", PUBLIC, "example.com", 1)


def test_probe_does_not_open_a_private_address() -> None:
    def opener(scheme: str, ip: str, sni: str, timeout: float) -> _Conn:
        raise AssertionError((scheme, ip, sni, timeout))

    snapshot = HttpProber(opener).probe("blog.example", "user.github.io", ("10.1.1.1",), 1)  # type: ignore[arg-type]
    assert snapshot.status is None
    assert snapshot.error == "refusing non-public address"


def test_https_failure_falls_back_to_http_and_sets_the_host_header() -> None:
    seen: list[str] = []
    conn = _Conn(404, b"There isn't a GitHub Pages site here")

    def opener(scheme: str, ip: str, sni: str, timeout: float) -> _Conn:
        del ip, sni, timeout
        seen.append(scheme)
        if scheme == "https":
            raise ssl.SSLCertVerificationError("bad certificate")
        return conn

    snapshot = HttpProber(opener).probe("blog.example", "user.github.io", (PUBLIC,), 1)  # type: ignore[arg-type]
    assert seen == ["https", "http"]
    assert snapshot.status == 404
    assert snapshot.body.startswith("There isn't")
    assert conn.closed is True
    assert conn.method == "GET"
    assert conn.path == "/"
    assert conn.headers is not None
    assert conn.headers["Host"] == "blog.example"
    assert conn.headers["User-Agent"] == USER_AGENT


def test_https_success_does_not_try_http() -> None:
    seen: list[str] = []

    def opener(scheme: str, ip: str, sni: str, timeout: float) -> _Conn:
        del ip, sni, timeout
        seen.append(scheme)
        return _Conn(200, b"ok-response")

    snapshot = HttpProber(opener).probe("blog.example", "user.github.io", (PUBLIC,), 1)  # type: ignore[arg-type]
    assert seen == ["https"]
    assert snapshot.status == 200
    assert snapshot.error is None


def test_body_is_capped() -> None:
    conn = _Conn(200, b"A" * 70_000 + b"NEEDLE!!")

    def opener(scheme: str, ip: str, sni: str, timeout: float) -> _Conn:
        del scheme, ip, sni, timeout
        return conn

    snapshot = HttpProber(opener).probe("blog.example", "user.github.io", (PUBLIC,), 1)  # type: ignore[arg-type]
    assert conn.response.amount == 65_536
    assert len(snapshot.body) == 65_536
    assert "NEEDLE" not in snapshot.body


def test_errors_name_the_scheme_and_stop_after_four_addresses() -> None:
    seen: list[str] = []

    def opener(scheme: str, ip: str, sni: str, timeout: float) -> _Conn:
        del sni, timeout
        seen.append(f"{scheme}:{ip}")
        if scheme == "https":
            raise TimeoutError()
        raise ConnectionRefusedError("no")

    addresses = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")
    snapshot = HttpProber(opener).probe("blog.example", "user.github.io", addresses, 1)  # type: ignore[arg-type]
    assert snapshot.error == "https timeout; http connection failed"
    assert seen == [f"{scheme}:{ip}" for scheme in ("https", "http") for ip in addresses[:4]]


def test_an_address_sni_skips_https() -> None:
    seen: list[str] = []

    def opener(scheme: str, ip: str, sni: str, timeout: float) -> _Conn:
        del ip, sni, timeout
        seen.append(scheme)
        return _Conn(200, b"ok-response")

    HttpProber(opener).probe("blog.example", "1.1.1.1", ("1.1.1.1",), 1)  # type: ignore[arg-type]
    assert seen == ["http"]
